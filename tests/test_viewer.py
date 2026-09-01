"""Local viewer: run summaries, manifest loading, and the token-gated server."""
from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from proofmark.viewer import _Handler, _list_runs, _run_manifest


def _make_run(base, name, findings):
    d = base / name
    d.mkdir()
    (d / "run.json").write_text(json.dumps({
        "target": "https://app.test", "model": "m", "operator": "me",
        "started_at": "2026-01-01T00:00:00", "findings": findings,
    }))


def test_list_runs_counts_severities(tmp_path):
    _make_run(tmp_path, "r1", [{"title": "SQLi", "severity": "critical"},
                               {"title": "XSS", "severity": "medium"}])
    runs = _list_runs(str(tmp_path))
    assert len(runs) == 1
    assert runs[0]["finding_count"] == 2
    assert runs[0]["severity"]["critical"] == 1 and runs[0]["severity"]["medium"] == 1
    assert runs[0]["target"] == "https://app.test"


def test_list_runs_empty_dir(tmp_path):
    assert _list_runs(str(tmp_path / "nope")) == []


def test_run_manifest_loads(tmp_path):
    _make_run(tmp_path, "r1", [{"title": "X", "severity": "low"}])
    assert _run_manifest(str(tmp_path), "r1")["target"] == "https://app.test"


def test_run_manifest_rejects_traversal(tmp_path):
    with pytest.raises(ValueError):
        _run_manifest(str(tmp_path), "../secrets")


def test_server_token_gating_and_data(tmp_path):
    _make_run(tmp_path, "r1", [{"title": "SQLi", "severity": "critical"}])
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.token = "secret123"
    httpd.runs_dir = str(tmp_path)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        # no token -> 403
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/runs", timeout=5)
        assert ei.value.code == 403

        # correct token -> JSON data
        body = urllib.request.urlopen(f"http://127.0.0.1:{port}/api/runs?t=secret123", timeout=5).read()
        data = json.loads(body)
        assert data[0]["name"] == "r1" and data[0]["severity"]["critical"] == 1

        # HTML shell with token
        html = urllib.request.urlopen(f"http://127.0.0.1:{port}/?t=secret123", timeout=5).read()
        assert b"Proofmark" in html
    finally:
        httpd.shutdown()
        httpd.server_close()
