"""Sandbox tests. Skipped automatically when Docker is not available, so the
offline suite still runs in a plain CI container."""
import json

import pytest

from proofmark.authorization import Authorization
from proofmark.sandbox import Sandbox, SandboxError
from proofmark.tools.http_tools import HttpRequestTool
from proofmark.http_client import HttpClient, RequestLog


def _docker_ok() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _docker_ok(), reason="Docker not available")


def test_a_command_runs_in_the_jail():
    with Sandbox() as sb:
        code, out = sb.exec("echo hello; id")
        assert code == 0 and "hello" in out


def test_the_runner_is_installed_outside_the_tmpfs():
    with Sandbox() as sb:
        code, out = sb.exec(f"ls {sb.runner_path}")
        assert code == 0


def test_the_http_tool_reaches_an_in_scope_host():
    with Sandbox() as sb:
        auth = Authorization.grant("https://api.github.com/zen", "tester", [])
        client = HttpClient(sb, auth, RequestLog())
        result = HttpRequestTool(client).run(method="GET", url="https://api.github.com/zen")
        assert "HTTP 200" in result.output and not result.is_error


def test_the_http_tool_refuses_out_of_scope():
    with Sandbox() as sb:
        auth = Authorization.grant("https://api.github.com/zen", "tester", [])
        client = HttpClient(sb, auth, RequestLog())
        result = HttpRequestTool(client).run(
            method="GET", url="http://169.254.169.254/latest/meta-data/")
        assert result.is_error


def test_a_code_target_can_be_read_and_searched(tmp_path):
    (tmp_path / "app.py").write_text(
        'PASSWORD = "planted-secret"\n'
        'q = "SELECT * FROM t WHERE id = \'%s\'" % request.args.get("id")\n'
    )
    from proofmark.tools.code_tools import ListFilesTool, ReadFileTool, SearchCodeTool
    with Sandbox() as sb:
        sb.copy_in(tmp_path)
        assert "app.py" in ListFilesTool(sb).run().output
        read = ReadFileTool(sb).run(path="app.py")
        assert "PASSWORD" in read.output and read.output.lstrip().startswith("1")
        found = SearchCodeTool(sb).run(pattern="PASSWORD")
        assert "planted-secret" in found.output


def test_reading_outside_the_source_root_is_refused():
    from proofmark.tools.code_tools import ReadFileTool
    with Sandbox() as sb:
        result = ReadFileTool(sb).run(path="../../etc/passwd")
        assert result.is_error


def test_capture_then_replay_with_a_mutation():
    """The proxy loop: send a request, then replay it with a changed field."""
    from proofmark.http_client import HttpClient, RequestLog
    from proofmark.tools.http_tools import HttpRequestTool, ListRequestsTool, ReplayRequestTool
    from proofmark.authorization import Authorization

    with Sandbox() as sb:
        auth = Authorization.grant("https://httpbingo.org/anything", "tester", [])
        client = HttpClient(sb, auth, RequestLog())

        sent = HttpRequestTool(client).run(method="GET", url="https://httpbingo.org/anything")
        assert "request #0" in sent.output

        listed = ListRequestsTool(client).run()
        assert "[0] GET" in listed.output

        # replay #0 as a POST with a body — the mutation the agent would make
        replayed = ReplayRequestTool(client).run(index=0, method="POST", body="probe=1")
        assert "replay of #0 as #1" in replayed.output and not replayed.is_error
        assert len(client.log) == 2


def test_replay_out_of_scope_is_still_refused():
    from proofmark.http_client import HttpClient, RequestLog, Request
    from proofmark.tools.http_tools import ReplayRequestTool
    from proofmark.authorization import Authorization
    with Sandbox() as sb:
        auth = Authorization.grant("https://api.github.com/zen", "tester", [])
        log = RequestLog()
        client = HttpClient(sb, auth, log)
        # seed a logged request, then try to replay it pointed at a new host
        client.send(Request("GET", "https://api.github.com/zen"))
        out = ReplayRequestTool(client).run(index=0, url="https://evil.test/x")
        assert out.is_error and "outside the authorized scope" in out.output


def test_recon_maps_a_live_site():
    """Smoke test: recon reaches a real page and returns a surface map."""
    from proofmark.http_client import HttpClient, RequestLog
    from proofmark.tools.recon_tool import ReconTool
    from proofmark.authorization import Authorization
    with Sandbox() as sb:
        auth = Authorization.grant("https://example.com/", "tester", [])
        client = HttpClient(sb, auth, RequestLog())
        # probe_paths off to keep the smoke test quick and quiet
        out = ReconTool(client).run(url="https://example.com/", probe_paths=False)
        assert not out.is_error
        assert "Mapped" in out.output and "page(s)" in out.output
