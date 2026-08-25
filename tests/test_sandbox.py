"""Sandbox tests. Skipped automatically when Docker is not available, so the
offline suite still runs in a plain CI container."""
import json

import pytest

from proofmark.authorization import Authorization
from proofmark.sandbox import Sandbox, SandboxError
from proofmark.tools.http_request import HttpRequestTool


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
        result = HttpRequestTool(sb, auth).run(method="GET", url="https://api.github.com/zen")
        data = json.loads(result.output)
        assert data.get("status") == 200


def test_the_http_tool_refuses_out_of_scope():
    with Sandbox() as sb:
        auth = Authorization.grant("https://api.github.com/zen", "tester", [])
        result = HttpRequestTool(sb, auth).run(
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
