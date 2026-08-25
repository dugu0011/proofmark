"""Reading an API description so the agent starts from a known map of endpoints.

Two formats people already have lying around: an OpenAPI / Swagger spec, and a
Postman collection. Either way the useful output is the same — a list of
(method, path) the agent should test, and a base URL to test them against. The
agent still has to *prove* each issue; the spec just saves it from guessing where
the endpoints are.

JSON is parsed with the standard library; YAML specs work when PyYAML is present.
"""
from __future__ import annotations

import json

_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")


def _load(text: str) -> dict | None:
    try:
        return json.loads(text)
    except ValueError:
        pass
    try:
        import yaml  # optional
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else None
    except Exception:  # noqa: BLE001 - no yaml, or not yaml
        return None


def sniff(text: str) -> str | None:
    """Return 'openapi', 'postman', or None."""
    data = _load(text)
    if not isinstance(data, dict):
        return None
    if "openapi" in data or "swagger" in data:
        return "openapi"
    if "info" in data and "item" in data:
        return "postman"
    return None


def parse(text: str) -> tuple[str | None, list[dict]]:
    """Return (base_url, endpoints). endpoints are {method, path/url, summary}."""
    kind = sniff(text)
    data = _load(text) or {}
    if kind == "openapi":
        return _openapi(data)
    if kind == "postman":
        return _postman(data)
    return None, []


def _openapi(spec: dict) -> tuple[str | None, list[dict]]:
    base = None
    servers = spec.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        base = servers[0].get("url")
    if not base and spec.get("host"):  # swagger 2.0
        scheme = (spec.get("schemes") or ["https"])[0]
        base = f"{scheme}://{spec['host']}{spec.get('basePath', '')}"

    endpoints = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method in _METHODS:
            op = item.get(method)
            if op is not None:
                endpoints.append({
                    "method": method.upper(), "path": path,
                    "summary": (op.get("summary") or op.get("operationId") or "")[:120]
                    if isinstance(op, dict) else "",
                })
    return base, endpoints


def _postman(spec: dict) -> tuple[str | None, list[dict]]:
    endpoints: list[dict] = []

    def walk(items):
        for it in items or []:
            if "item" in it:                     # a folder
                walk(it["item"])
                continue
            req = it.get("request")
            if not isinstance(req, dict):
                continue
            method = str(req.get("method", "GET")).upper()
            url = req.get("url")
            raw = url.get("raw") if isinstance(url, dict) else url
            if raw:
                endpoints.append({"method": method, "path": str(raw),
                                  "summary": (it.get("name") or "")[:120]})

    walk(spec.get("item"))
    return None, endpoints


def briefing(base: str | None, endpoints: list[dict], limit: int = 60) -> str:
    """A compact endpoint map to hand the agent."""
    lines = ["Known endpoints from the provided API spec — start by testing these, "
             "but also look for what the spec omits:"]
    for ep in endpoints[:limit]:
        summ = f"  — {ep['summary']}" if ep.get("summary") else ""
        lines.append(f"  {ep['method']} {ep['path']}{summ}")
    if len(endpoints) > limit:
        lines.append(f"  …and {len(endpoints) - limit} more.")
    return "\n".join(lines)
