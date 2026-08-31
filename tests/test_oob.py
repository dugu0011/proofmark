"""Out-of-band interaction listener + the canary/check tools.

Uses real localhost HTTP round-trips against an ephemeral port — no external
network, so it runs anywhere the test suite runs.
"""
from __future__ import annotations

import http.client
import urllib.request

import pytest

from proofmark.oob import InteractionServer
from proofmark.tools.oob_tool import OobCanaryTool, OobCheckTool


@pytest.fixture
def server():
    s = InteractionServer(bind_host="127.0.0.1", bind_port=0, public_host="127.0.0.1")
    try:
        yield s
    finally:
        s.close()


def _hit(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read().decode()


# --------------------------------------------------------------------- server


def test_canary_url_records_a_hit(server):
    token = server.new_canary("ssrf test")
    assert server.interactions(token) == []          # nothing yet
    assert _hit(server.http_url(token)) == "ok"
    hits = server.interactions(token)
    assert len(hits) == 1
    assert hits[0].method == "GET"
    assert token in hits[0].path


def test_token_in_host_header_is_recorded(server):
    token = server.new_canary()
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    conn.putrequest("GET", "/not-a-token", skip_host=True)
    conn.putheader("Host", f"{token}.attacker.example")
    conn.endheaders()
    conn.getresponse().read()
    conn.close()
    hits = server.interactions(token)
    assert len(hits) == 1
    assert token in hits[0].host


def test_unrelated_request_is_not_attributed(server):
    token = server.new_canary()
    _hit(f"http://127.0.0.1:{server.port}/nothing-here")
    assert server.interactions(token) == []


def test_http_url_and_dns_host_shapes(server):
    token = server.new_canary()
    assert server.http_url(token).endswith(f":{server.port}/{token}")
    # public_host is an IP here, so there is no usable DNS canary
    assert "no DNS canary" in server.dns_host(token)


# ---------------------------------------------------------------------- tools


def test_check_tool_flips_to_confirmed_after_a_hit(server):
    canary = OobCanaryTool(server)
    check = OobCheckTool(server)

    minted = canary.run(hint="blind rce")
    token = minted.data["token"]
    assert token in minted.output

    before = check.run(token=token)
    assert "No out-of-band interactions" in before.output

    _hit(server.http_url(token))

    after = check.run(token=token)
    assert "CONFIRMED" in after.output
    assert after.data["count"] == 1


def test_check_tool_requires_a_token(server):
    result = OobCheckTool(server).run(token="")
    assert result.is_error


def test_check_tool_output_is_fenced_as_untrusted(server):
    # interaction details are target-controlled and must be fenced by the loop
    assert OobCheckTool(server).returns_untrusted_data is True
