"""Connect to external MCP servers and expose their tools to the agent.

List servers in ~/.proofmark/mcp-servers.json (or $PROOFMARK_MCP_CONFIG): each is a
local `stdio` server Proofmark launches, or a remote `http` server. Their tools are
namespaced `<server>_<tool>` and handed to the agent alongside the built-ins.

Everything here is guarded: no config file, an unparsable one, a missing `mcp`
package, or a server that fails to connect all resolve to "no extra tools" — a
normal scan is never affected. Mirrors Strix's ~/.strix/mcp-servers.json.
"""
from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path

from proofmark.tools.base import Tool, ToolResult

DEFAULT_CONFIG = "~/.proofmark/mcp-servers.json"
_CALL_TIMEOUT = 60


def config_path() -> Path:
    return Path(os.environ.get("PROOFMARK_MCP_CONFIG", DEFAULT_CONFIG)).expanduser()


def read_config(path: Path) -> list[dict]:
    """Parse the server list. Missing/invalid file -> [] (never raises)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, list):
        return []
    out = []
    for s in data:
        if isinstance(s, dict) and s.get("name") and s.get("transport") in ("stdio", "http"):
            out.append(s)
    return out


class _MCPTool(Tool):
    """Adapter: one external MCP tool, callable through Proofmark's sync tool loop."""
    returns_untrusted_data = True

    def __init__(self, manager, server: str, tool: str, description: str, schema: dict):
        self._mgr = manager
        self._server = server
        self._tool = tool
        self.name = f"{server}_{tool}"[:64]
        self.description = (description or f"{tool} (via MCP server {server})")[:1024]
        self.parameters = schema or {"type": "object", "properties": {}}

    def run(self, **kwargs) -> ToolResult:
        try:
            text = self._mgr.call(self._server, self._tool, kwargs)
            return ToolResult(text)
        except Exception as exc:  # noqa: BLE001 - an MCP failure must not crash the loop
            return ToolResult(f"MCP tool {self.name} failed: {type(exc).__name__}: {exc}", is_error=True)


class MCPManager:
    """Owns a background asyncio loop that keeps the MCP sessions open for the run."""

    def __init__(self):
        self.loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._sessions: dict = {}
        self._stack = None
        self._stop: asyncio.Event | None = None

    # --- lifecycle ----------------------------------------------------------

    def start(self, servers: list[dict]) -> list[Tool]:
        """Connect to every server; return the adapter tools (empty on any failure)."""
        try:
            import mcp  # noqa: F401
        except ImportError:
            print("MCP servers are configured but the 'mcp' package is not installed "
                  "(pip install 'proofmark[mcp]'); skipping them.")
            return []

        self.loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        try:
            fut = asyncio.run_coroutine_threadsafe(self._setup(servers), self.loop)
            tool_specs = fut.result(timeout=45)
        except Exception as exc:  # noqa: BLE001
            print(f"MCP setup failed: {exc}; continuing without external tools.")
            self.close()
            return []
        return [_MCPTool(self, s["server"], s["tool"], s["description"], s["schema"]) for s in tool_specs]

    def _run_loop(self):
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    async def _setup(self, servers: list[dict]) -> list[dict]:
        from contextlib import AsyncExitStack

        from mcp import ClientSession
        self._stack = AsyncExitStack()
        self._stop = asyncio.Event()
        specs: list[dict] = []
        for srv in servers:
            name = srv["name"]
            try:
                session = await self._connect(srv)
                await session.initialize()
                self._sessions[name] = session
                listed = await session.list_tools()
                allow = srv.get("allowed_tools")
                for t in listed.tools:
                    if allow and t.name not in allow:
                        continue
                    specs.append({"server": name, "tool": t.name,
                                  "description": t.description or "",
                                  "schema": getattr(t, "inputSchema", None) or {}})
            except Exception as exc:  # noqa: BLE001 - one bad server is skipped, not fatal
                print(f"  MCP server '{name}' skipped: {type(exc).__name__}: {exc}")
        return specs

    async def _connect(self, srv: dict):
        from mcp import ClientSession
        if srv["transport"] == "stdio":
            from mcp import StdioServerParameters
            from mcp.client.stdio import stdio_client
            params = StdioServerParameters(command=srv["command"], args=srv.get("args", []),
                                           env=srv.get("env"))
            read, write = await self._stack.enter_async_context(stdio_client(params))
        else:  # http
            from mcp.client.streamable_http import streamablehttp_client
            headers = None
            auth = srv.get("auth") or {}
            if auth.get("kind") == "bearer" and auth.get("token"):
                headers = {"Authorization": f"Bearer {auth['token']}"}
            ctx = await self._stack.enter_async_context(streamablehttp_client(srv["url"], headers=headers))
            read, write = ctx[0], ctx[1]
        return await self._stack.enter_async_context(ClientSession(read, write))

    # --- invocation (sync, from the tool loop) ------------------------------

    def call(self, server: str, tool: str, args: dict) -> str:
        async def _c():
            res = await self._sessions[server].call_tool(tool, args or {})
            parts = []
            for c in getattr(res, "content", []) or []:
                parts.append(getattr(c, "text", None) or str(c))
            return "\n".join(parts) if parts else "(no content)"
        return asyncio.run_coroutine_threadsafe(_c(), self.loop).result(timeout=_CALL_TIMEOUT)

    def close(self):
        if self.loop is None:
            return
        try:
            async def _shut():
                if self._stack is not None:
                    await self._stack.aclose()
            asyncio.run_coroutine_threadsafe(_shut(), self.loop).result(timeout=15)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.loop.call_soon_threadsafe(self.loop.stop)
        except Exception:  # noqa: BLE001
            pass


def load_tools(path: Path | None = None) -> tuple[list[Tool], "MCPManager | None"]:
    """Adapter tools for every configured MCP server, plus the manager to close.

    Returns ([], None) when there is nothing to do — no config, or none valid."""
    servers = read_config(path or config_path())
    if not servers:
        return [], None
    mgr = MCPManager()
    tools = mgr.start(servers)
    if not tools:
        mgr.close()
        return [], None
    print(f"MCP: loaded {len(tools)} tool(s) from {len(servers)} server(s).")
    return tools, mgr
