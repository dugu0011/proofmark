"""Tamper-evident, replayable run records — the thing a security team needs
before it will let an autonomous agent exploit its systems.

Every run is written to disk as a manifest: what was authorized, what the agent
did step by step, every request it sent, and what it proved. The steps are
hash-chained — step_hash = sha256(prev_hash + canonical(step)) — so any later
edit, deletion or reorder breaks the chain and `verify` catches it. If a signing
key is set, the whole manifest is HMAC-signed too, so the record is not just
unaltered but attributable.

Because every request is recorded, a run is *replayable*: `replay` re-issues the
in-scope requests against the target and reports whether the exploit still works.
A signed record plus a passing replay is a durable, checkable proof that a
finding was real — and still is.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64
SIGNING_KEY_ENV = "PROOFMARK_SIGNING_KEY"
RUNS_DIR = "proofmark_runs"


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _hash(prev: str, entry: dict) -> str:
    return hashlib.sha256((prev + _canonical(entry)).encode()).hexdigest()


@dataclass
class RunRecord:
    run_id: str
    product: str
    version: str
    target: str
    kind: str
    operator: str
    model: str
    authorization: dict
    started_at: str
    finished_at: str
    stopped_reason: str
    steps: list[dict] = field(default_factory=list)      # {i, kind, text, detail}
    requests: list[dict] = field(default_factory=list)   # {method, url, status, error}
    findings: list[dict] = field(default_factory=list)

    def chained_steps(self) -> list[dict]:
        """Steps with a hash chain over them."""
        out, prev = [], GENESIS
        for i, step in enumerate(self.steps):
            core = {"i": i, "kind": step.get("kind"), "text": step.get("text", ""),
                    "detail": step.get("detail", "")}
            h = _hash(prev, core)
            out.append({**core, "hash": h})
            prev = h
        return out

    def manifest(self) -> dict:
        steps = self.chained_steps()
        body = {
            "run_id": self.run_id, "product": self.product, "version": self.version,
            "target": self.target, "kind": self.kind, "operator": self.operator,
            "model": self.model, "authorization": self.authorization,
            "started_at": self.started_at, "finished_at": self.finished_at,
            "stopped_reason": self.stopped_reason,
            "steps": steps, "requests": self.requests, "findings": self.findings,
            "chain_tip": steps[-1]["hash"] if steps else GENESIS,
        }
        key = os.environ.get(SIGNING_KEY_ENV)
        if key:
            body["signature"] = "hmac-sha256:" + hmac.new(
                key.encode(), _canonical(body).encode(), hashlib.sha256).hexdigest()
        return body


def save(record: RunRecord, base_dir: str = RUNS_DIR) -> Path:
    out = Path(base_dir) / record.run_id
    out.mkdir(parents=True, exist_ok=True)
    manifest = record.manifest()
    (out / "run.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return out


def load(run_dir: str) -> dict:
    return json.loads((Path(run_dir) / "run.json").read_text(encoding="utf-8"))


def verify(run_dir: str) -> tuple[bool, str]:
    """Recompute the chain (and the signature, if present). Returns (ok, reason)."""
    try:
        manifest = load(run_dir)
    except FileNotFoundError:
        return False, "no run.json in that directory"
    except ValueError as exc:
        return False, f"run.json is not valid JSON: {exc}"

    # 1. hash chain over steps
    prev = GENESIS
    for step in manifest.get("steps", []):
        core = {"i": step.get("i"), "kind": step.get("kind"),
                "text": step.get("text", ""), "detail": step.get("detail", "")}
        expected = _hash(prev, core)
        if step.get("hash") != expected:
            return False, f"chain broken at step {step.get('i')} — record was altered"
        prev = expected
    if manifest.get("chain_tip", GENESIS) != prev:
        return False, "chain tip does not match — a step was added or removed"

    # 2. signature, if the record carries one
    sig = manifest.get("signature")
    if sig:
        key = os.environ.get(SIGNING_KEY_ENV)
        if not key:
            return False, f"record is signed but {SIGNING_KEY_ENV} is not set to check it"
        body = {k: v for k, v in manifest.items() if k != "signature"}
        expected = "hmac-sha256:" + hmac.new(
            key.encode(), _canonical(body).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return False, "signature does not match — record was altered or the wrong key"
        return True, "intact and signature valid"

    return True, "intact (unsigned — set a signing key for attributable records)"


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
