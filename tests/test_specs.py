"""Spec ingestion: extract a clean endpoint map from OpenAPI and Postman, so the
agent starts from what exists instead of guessing."""
import json

from proofmark import specs

OPENAPI = json.dumps({
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/users/{id}": {
            "get": {"summary": "Get a user"},
            "delete": {"operationId": "deleteUser"},
        },
        "/login": {"post": {"summary": "Authenticate"}},
    },
})

SWAGGER2 = json.dumps({
    "swagger": "2.0", "host": "api.example.com", "basePath": "/v2", "schemes": ["https"],
    "paths": {"/ping": {"get": {"summary": "health"}}},
})

POSTMAN = json.dumps({
    "info": {"name": "My API"},
    "item": [
        {"name": "List users", "request": {"method": "GET",
         "url": {"raw": "https://api.example.com/users"}}},
        {"name": "Folder", "item": [
            {"name": "Create", "request": {"method": "POST",
             "url": "https://api.example.com/users"}}]},
    ],
})


def test_sniff_recognizes_each_format():
    assert specs.sniff(OPENAPI) == "openapi"
    assert specs.sniff(SWAGGER2) == "openapi"
    assert specs.sniff(POSTMAN) == "postman"
    assert specs.sniff('{"just": "json"}') is None
    assert specs.sniff("not a spec at all") is None


def test_openapi_endpoints_and_base_url():
    base, endpoints = specs.parse(OPENAPI)
    assert base == "https://api.example.com/v1"
    pairs = {(e["method"], e["path"]) for e in endpoints}
    assert ("GET", "/users/{id}") in pairs
    assert ("DELETE", "/users/{id}") in pairs
    assert ("POST", "/login") in pairs
    assert len(endpoints) == 3


def test_swagger2_host_becomes_a_base_url():
    base, endpoints = specs.parse(SWAGGER2)
    assert base == "https://api.example.com/v2"
    assert endpoints[0]["method"] == "GET" and endpoints[0]["path"] == "/ping"


def test_postman_walks_folders():
    base, endpoints = specs.parse(POSTMAN)
    assert base is None
    urls = {(e["method"], e["path"]) for e in endpoints}
    assert ("GET", "https://api.example.com/users") in urls
    assert ("POST", "https://api.example.com/users") in urls


def test_briefing_lists_endpoints_for_the_agent():
    _, endpoints = specs.parse(OPENAPI)
    text = specs.briefing("https://api.example.com/v1", endpoints)
    assert "Known endpoints" in text
    assert "GET /users/{id}" in text and "POST /login" in text
