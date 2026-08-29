"""Multi-identity HTTP and the authz_probe tool (BOLA/IDOR, BFLA)."""
from __future__ import annotations

import json

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, Request, RequestLog
from proofmark.tools.authz_tool import AuthzProbeTool


class RoleSandbox:
    """A runner stand-in that answers by whichever Authorization it sees, so a
    test can prove each identity's credentials actually reach the wire."""

    def __init__(self, by_auth: dict[str, dict]) -> None:
        self.runner_path = "/runner.py"
        self._by_auth = by_auth
        self.seen: list[str | None] = []

    def exec(self, cmd, timeout=None):
        spec = json.loads(cmd[-1])
        auth = (spec.get("headers") or {}).get("Authorization")
        self.seen.append(auth)
        resp = self._by_auth.get(auth) or self._by_auth.get(None)
        return 0, json.dumps(resp)


def _auth():
    return Authorization.grant("https://app.test", "me")


def _client(sandbox, identities=None):
    return HttpClient(
        sandbox, _auth(), RequestLog(), safe_mode=True,
        auth_headers={"Authorization": "Bearer owner"}, identities=identities,
    )


# ------------------------------------------------------------------ identities

def test_alternate_identities_includes_configured_and_anonymous():
    c = _client(RoleSandbox({}), identities={"second_user": {"headers": {}, "label": "second user"}})
    assert c.alternate_identities() == ["second_user", "anonymous"]
    # with nothing configured, anonymous is still available to compare against
    assert _client(RoleSandbox({})).alternate_identities() == ["anonymous"]


def test_each_identity_sends_its_own_credentials():
    ident = {"second_user": {"headers": {"Authorization": "Bearer other"}, "label": "second user"}}
    resp = {"status": 200, "body": "x", "headers": {}, "elapsed_ms": 1}
    sb = RoleSandbox({"Bearer owner": resp, "Bearer other": resp, None: resp})
    c = _client(sb, identities=ident)
    req = Request("GET", "https://app.test/api/orders/1")
    c.send(req)                       # primary
    c.send(req, identity="second_user")
    c.send(req, identity="anonymous")
    assert sb.seen == ["Bearer owner", "Bearer other", None]


def test_cache_does_not_bleed_across_identities():
    resp = {"status": 200, "body": "x", "headers": {}, "elapsed_ms": 1}
    sb = RoleSandbox({"Bearer owner": resp, None: resp})
    c = _client(sb)
    req = Request("GET", "https://app.test/")
    c.send(req)                       # primary -> real call
    c.send(req, identity="anonymous") # different creds -> must not use primary's cache
    assert sb.seen == ["Bearer owner", None]


# ------------------------------------------------------------------ authz_probe

def test_probe_flags_a_second_user_reaching_the_owners_object():
    owner = {"status": 200, "body": "order 123: alice's data", "headers": {}, "elapsed_ms": 1}
    forbidden = {"status": 403, "body": "forbidden", "headers": {}, "elapsed_ms": 1}
    # The bug: the second user's token returns alice's object too.
    sb = RoleSandbox({"Bearer owner": owner, "Bearer other": owner, None: forbidden})
    ident = {"second_user": {"headers": {"Authorization": "Bearer other"}, "label": "second user"}}
    c = _client(sb, ident)

    # the agent first fetches its own object, then probes it
    c.send(Request("GET", "https://app.test/api/orders/123"))
    out = AuthzProbeTool(c).run(index=0)

    assert not out.is_error
    text = out.output
    assert "second user" in text
    assert "broken access control" in text.lower()      # second user got the same 200
    assert "denied" in text.lower()                       # anonymous was 403


def test_probe_says_access_control_holds_when_others_are_denied():
    owner = {"status": 200, "body": "alice's data", "headers": {}, "elapsed_ms": 1}
    forbidden = {"status": 403, "body": "no", "headers": {}, "elapsed_ms": 1}
    sb = RoleSandbox({"Bearer owner": owner, "Bearer other": forbidden, None: forbidden})
    ident = {"second_user": {"headers": {"Authorization": "Bearer other"}, "label": "second user"}}
    c = _client(sb, ident)
    c.send(Request("GET", "https://app.test/api/orders/123"))
    out = AuthzProbeTool(c).run(index=0)
    assert "enforced" in out.output.lower()
    assert "broken access control" not in out.output.lower()


def test_probe_needs_a_real_request_number():
    c = _client(RoleSandbox({}))
    assert AuthzProbeTool(c).run(index=99).is_error


def test_probe_without_a_second_identity_still_offers_anonymous():
    owner = {"status": 200, "body": "data", "headers": {}, "elapsed_ms": 1}
    forbidden = {"status": 401, "body": "login", "headers": {}, "elapsed_ms": 1}
    sb = RoleSandbox({"Bearer owner": owner, None: forbidden})
    c = _client(sb)  # no configured second identity
    c.send(Request("GET", "https://app.test/api/me"))
    out = AuthzProbeTool(c).run(index=0)
    assert not out.is_error
    assert "anonymous" in out.output.lower()
