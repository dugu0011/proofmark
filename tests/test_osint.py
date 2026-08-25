"""Passive subdomain discovery: parsing, and the domain heuristic."""
import json
from proofmark.osint import parse_crtsh, registered_domain


def test_registered_domain():
    assert registered_domain("api.example.com") == "example.com"
    assert registered_domain("https://staging.app.example.com/x") == "example.com"
    assert registered_domain("example.com") == "example.com"
    assert registered_domain("localhost") == "localhost"


def test_parse_crtsh_extracts_distinct_subdomains():
    rows = json.dumps([
        {"name_value": "api.example.com\nwww.example.com"},
        {"name_value": "*.example.com"},
        {"name_value": "admin.example.com"},
        {"name_value": "not-ours.other.com"},     # different domain, ignored
        {"name_value": "example.com"},
    ])
    subs = parse_crtsh(rows, "example.com")
    assert subs == {"api.example.com", "www.example.com", "admin.example.com", "example.com"}
    assert "not-ours.other.com" not in subs


def test_parse_crtsh_tolerates_garbage():
    assert parse_crtsh("not json", "example.com") == set()
    assert parse_crtsh("{}", "example.com") == set()
