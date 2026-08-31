"""Config-file loading (--config)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from proofmark.appconfig import ConfigError, load_config
from proofmark.cli import main


def test_load_json_and_flatten_login(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"target": "https://app.test", "model": "azure/gpt-4.1",
                             "rps": 5, "login": {"url": "https://app.test/login",
                                                 "username": "you", "password": "pw"}}))
    cfg = load_config(str(p))
    assert cfg["target"] == "https://app.test"
    assert cfg["model"] == "azure/gpt-4.1" and cfg["rps"] == 5
    assert cfg["login_url"] == "https://app.test/login"     # flattened
    assert cfg["username"] == "you" and cfg["password"] == "pw"
    assert "login" not in cfg


def test_invalid_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not json")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_non_mapping_raises(tmp_path):
    p = tmp_path / "list.json"
    p.write_text("[1, 2, 3]")
    with pytest.raises(ConfigError):
        load_config(str(p))


def test_config_supplies_target_so_dash_t_is_optional(tmp_path):
    """A config providing `target` satisfies the required -t: the command gets past
    option parsing to the authorization check (no 'Missing option' error)."""
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"target": "https://app.test"}))
    result = CliRunner().invoke(main, ["scan", "--config", str(p)])   # no --authorized
    assert "Missing option" not in result.output and "-t" not in result.output.split("\n")[0]
    assert "authorized" in result.output.lower()                       # reached the auth gate


def test_yaml_config_if_pyyaml_present(tmp_path):
    pytest.importorskip("yaml")
    p = tmp_path / "c.yaml"
    p.write_text("target: https://app.test\nrps: 3\nlogin:\n  url: https://app.test/login\n  username: u\n")
    cfg = load_config(str(p))
    assert cfg["target"] == "https://app.test" and cfg["rps"] == 3
    assert cfg["login_url"] == "https://app.test/login" and cfg["username"] == "u"
