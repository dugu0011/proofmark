"""MCP client: config parsing, the tool adapter, and the inert (no-config) path."""
from __future__ import annotations

import json

from proofmark.mcp_client import _MCPTool, load_tools, read_config


def test_read_config_keeps_only_valid_entries(tmp_path):
    f = tmp_path / "c.json"
    f.write_text(json.dumps([
        {"name": "fs", "transport": "stdio", "command": "npx", "args": ["x"]},
        {"name": "gh", "transport": "http", "url": "https://x"},
        {"bad": "entry"},                       # no name/transport -> dropped
        {"name": "n", "transport": "weird"},    # bad transport -> dropped
    ]))
    cfg = read_config(f)
    assert [c["name"] for c in cfg] == ["fs", "gh"]


def test_read_config_missing_file(tmp_path):
    assert read_config(tmp_path / "nope.json") == []


def test_read_config_not_a_list(tmp_path):
    f = tmp_path / "c.json"
    f.write_text('{"name": "x"}')
    assert read_config(f) == []


def test_load_tools_no_config_is_inert(tmp_path):
    tools, mgr = load_tools(tmp_path / "nope.json")
    assert tools == [] and mgr is None


class _FakeMgr:
    def call(self, server, tool, args):
        return f"ran {server}.{tool} with {sorted(args)}"


class _BadMgr:
    def call(self, *a):
        raise RuntimeError("boom")


def test_adapter_namespaces_and_calls():
    t = _MCPTool(_FakeMgr(), "fs", "read_file", "Read a file", {"type": "object"})
    assert t.name == "fs_read_file"
    assert "via MCP" not in t.description  # kept the provided description
    out = t.run(path="/x")
    assert out.output == "ran fs.read_file with ['path']" and not out.is_error


def test_adapter_wraps_failures():
    out = _MCPTool(_BadMgr(), "s", "t", "", {}).run()
    assert out.is_error and "boom" in out.output
