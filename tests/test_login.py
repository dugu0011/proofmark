"""Login helper — username/password -> session (cookie or token)."""
from __future__ import annotations

from proofmark.login import parse_set_cookie, perform_login

URL = "https://app.test/login"


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.sent = None

    def send_full(self, request, identity=None):
        self.sent = request
        return self.response


def test_cookie_login():
    c = FakeClient({"status": 200, "headers": {"Set-Cookie": "session=abc123; Path=/; HttpOnly"},
                    "body": "{}"})
    r = perform_login(c, URL, "u", "p")
    assert r.ok and r.cookies == {"session": "abc123"}
    assert c.sent.body == "username=u&password=p"                       # form by default
    assert c.sent.headers["Content-Type"] == "application/x-www-form-urlencoded"


def test_token_login_json():
    c = FakeClient({"status": 200, "headers": {}, "body": '{"token":"eyJabcdefghij"}'})
    r = perform_login(c, URL, "u", "p", as_json=True)
    assert r.ok and r.headers == {"Authorization": "Bearer eyJabcdefghij"}
    assert c.sent.headers["Content-Type"] == "application/json"


def test_nested_token():
    c = FakeClient({"status": 200, "headers": {}, "body": '{"data":{"accessToken":"tok12345678"}}'})
    r = perform_login(c, URL, "u", "p")
    assert r.ok and r.headers["Authorization"] == "Bearer tok12345678"


def test_no_session_found():
    c = FakeClient({"status": 200, "headers": {}, "body": "welcome home"})
    r = perform_login(c, URL, "u", "p")
    assert not r.ok and "no session" in r.detail


def test_error_response():
    c = FakeClient({"error": "out of scope: https://x"})
    r = perform_login(c, URL, "u", "p")
    assert not r.ok and "failed" in r.detail


def test_custom_field_names():
    c = FakeClient({"status": 200, "headers": {"Set-Cookie": "sid=x"}, "body": "{}"})
    perform_login(c, URL, "admin", "pw", user_field="email", pass_field="pass")
    assert "email=admin" in c.sent.body and "pass=pw" in c.sent.body


def test_parse_set_cookie():
    assert parse_set_cookie("session=abc; Path=/; HttpOnly; Secure") == {"session": "abc"}
    assert parse_set_cookie(["a=1", "b=2; Path=/"]) == {"a": "1", "b": "2"}
    assert parse_set_cookie(None) == {}
