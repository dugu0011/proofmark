"""Load scan options from a config file, so a long flag line becomes one file.

Keys match the CLI option names (dashes as underscores): target, model, operator,
rps, sarif, fail_on, max_steps, strategy, baseline, allow_hosts, login_url,
username, password, ... A convenience `login:` block (url/username/password) is
flattened. CLI flags always override the file. JSON always works; YAML needs
pyyaml.
"""
from __future__ import annotations

import json


class ConfigError(Exception):
    pass


def load_config(path: str) -> dict:
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as exc:
        raise ConfigError(f"could not read config {path}: {exc}") from exc

    if path.endswith((".yml", ".yaml")):
        try:
            import yaml
        except ImportError as exc:
            raise ConfigError("YAML config needs pyyaml (`pip install pyyaml`) — or use a .json "
                              "config.") from exc
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    else:
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ConfigError(f"invalid JSON in {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigError(f"config {path} must be a mapping of option -> value.")

    # --target is a repeatable (multiple) option now, so a scalar target in the
    # config must become a one-element list to populate it via default_map.
    if isinstance(data.get("target"), str):
        data["target"] = [data["target"]]
    login = data.pop("login", None)
    if isinstance(login, dict):
        if "url" in login:
            data.setdefault("login_url", login["url"])
        if "username" in login:
            data.setdefault("username", login["username"])
        if "password" in login:
            data.setdefault("password", login["password"])
    return data
