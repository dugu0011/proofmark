"""Sandbox-backed tests. Skipped automatically when Docker is unavailable, so the
offline suite still runs in a plain CI container."""
import json

import pytest

from proofmark.authorization import Authorization
from proofmark.http_client import HttpClient, Request, RequestLog
from proofmark.sandbox import Sandbox
from proofmark.tools.http_tools import HttpRequestTool, ListRequestsTool, ReplayRequestTool


def _docker_ok() -> bool:
    try:
        import docker
        docker.from_env().ping()
        return True
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(not _docker_ok(), reason="Docker not available")


# ---------------------------------------------------------------- basics
def test_a_command_runs_in_the_jail():
    with Sandbox() as sb:
        code, out = sb.exec("echo hello; id")
        assert code == 0 and "hello" in out


def test_the_runner_is_installed_outside_the_tmpfs():
    with Sandbox() as sb:
        code, _ = sb.exec(f"ls {sb.runner_path}")
        assert code == 0


# ---------------------------------------------------------------- http + proxy
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


def test_capture_then_replay_with_a_mutation():
    with Sandbox() as sb:
        auth = Authorization.grant("https://httpbingo.org/anything", "tester", [])
        client = HttpClient(sb, auth, RequestLog())
        sent = HttpRequestTool(client).run(method="GET", url="https://httpbingo.org/anything")
        assert "request #0" in sent.output
        listed = ListRequestsTool(client).run()
        assert "[0] GET" in listed.output
        replayed = ReplayRequestTool(client).run(index=0, method="POST", body="probe=1")
        assert "replay of #0 as #1" in replayed.output and not replayed.is_error
        assert len(client.log) == 2


def test_replay_out_of_scope_is_still_refused():
    with Sandbox() as sb:
        auth = Authorization.grant("https://api.github.com/zen", "tester", [])
        client = HttpClient(sb, auth, RequestLog())
        client.send(Request("GET", "https://api.github.com/zen"))
        out = ReplayRequestTool(client).run(index=0, url="https://evil.test/x")
        assert out.is_error and "outside the authorized scope" in out.output


# ---------------------------------------------------------------- code target
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


# ---------------------------------------------------------------- recon
def test_recon_maps_a_live_site():
    from proofmark.tools.recon_tool import ReconTool
    with Sandbox() as sb:
        auth = Authorization.grant("https://example.com/", "tester", [])
        client = HttpClient(sb, auth, RequestLog())
        out = ReconTool(client).run(url="https://example.com/", probe_paths=False)
        assert not out.is_error and "Mapped" in out.output


# ---------------------------------------------------------------- propose_fix
def test_propose_fix_accepts_a_valid_patch_and_refuses_a_bad_one(tmp_path):
    (tmp_path / "db.py").write_text(
        'def user(uid):\n'
        '    q = "SELECT * FROM users WHERE id = \'%s\'" % uid\n'
        '    return q\n'
    )
    from proofmark.tools.fix_tool import FixLog, ProposeFixTool
    good = (
        "@@ -1,3 +1,3 @@\n"
        " def user(uid):\n"
        "-    q = \"SELECT * FROM users WHERE id = '%s'\" % uid\n"
        "+    q = (\"SELECT * FROM users WHERE id = ?\", (uid,))\n"
        "     return q\n"
    )
    bad = (
        "@@ -1,3 +1,3 @@\n"
        " def user(uid):\n"
        "-    q = \"NOT THE REAL LINE\"\n"
        "+    q = \"safe\"\n"
        "     return q\n"
    )
    with Sandbox() as sb:
        sb.copy_in(tmp_path)
        log = FixLog()
        ok = ProposeFixTool(sb, log).run(file="db.py", unified_diff=good, explanation="parameterize")
        assert not ok.is_error and len(log.fixes) == 1
        no = ProposeFixTool(sb, log).run(file="db.py", unified_diff=bad)
        assert no.is_error and "does not apply" in no.output
        assert len(log.fixes) == 1
