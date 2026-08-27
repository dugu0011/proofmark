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
# HMAC (shared-secret) signing — anyone verifying needs the same secret.
SIGNING_KEY_ENV = "PROOFMARK_SIGNING_KEY"
# Ed25519 (public-key) signing — the private key signs, and the matching public
# key (published, embedded in the record) lets ANYONE verify without a secret.
# This is the "verify it yourself" property an auditor or customer needs.
SIGNING_PRIVATE_ENV = "PROOFMARK_SIGNING_PRIVATE_KEY"
SIGNING_PUBLIC_ENV = "PROOFMARK_SIGNING_PUBLIC_KEY"   # optional pin, checked on verify
RUNS_DIR = "proofmark_runs"


def _load_ed25519_private():
    """Read PROOFMARK_SIGNING_PRIVATE_KEY as a 64-char hex seed, a PEM string, or a
    path to a file holding either. Returns a private key object or None."""
    raw = os.environ.get(SIGNING_PRIVATE_ENV)
    if not raw:
        return None
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization  # noqa: F401
    text = raw.strip()
    if os.path.exists(text):
        with open(text, "rb") as fh:
            blob = fh.read()
        text = blob.decode("utf-8", "replace").strip()
        if b"BEGIN" in blob:
            return serialization.load_pem_private_key(blob, password=None)
    if "BEGIN" in text:
        return serialization.load_pem_private_key(text.encode(), password=None)
    seed = bytes.fromhex(text)
    if len(seed) != 32:
        raise ValueError("ed25519 private seed must be 32 bytes (64 hex chars)")
    return Ed25519PrivateKey.from_private_bytes(seed)


def _ed25519_public_hex(priv) -> str:
    from cryptography.hazmat.primitives import serialization
    return priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _ed25519_verify(public_field: str, message: str, signature: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
    hexkey = public_field.split(":", 1)[1] if ":" in public_field else public_field
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey))
    try:
        pub.verify(signature, message.encode())
        return True
    except InvalidSignature:
        return False


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
    fixes: list[dict] = field(default_factory=list)      # {file, diff, explanation}
    usage: dict = field(default_factory=dict)            # tokens + estimated cost

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
            "fixes": self.fixes, "usage": self.usage,
            "chain_tip": steps[-1]["hash"] if steps else GENESIS,
        }
        priv = _load_ed25519_private()
        if priv is not None:
            # Public key goes INTO the signed body, so the signature attests to it
            # too and a verifier reads the signer's identity straight from the record.
            body["public_key"] = "ed25519:" + _ed25519_public_hex(priv)
            body["signature"] = "ed25519:" + priv.sign(_canonical(body).encode()).hex()
            return body
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
    if sig and sig.startswith("ed25519:"):
        pub = manifest.get("public_key", "")
        if not pub:
            return False, "record is ed25519-signed but carries no public key"
        body = {k: v for k, v in manifest.items() if k != "signature"}
        try:
            ok = _ed25519_verify(pub, _canonical(body), bytes.fromhex(sig.split(":", 1)[1]))
        except ImportError:
            return False, "install 'cryptography' to verify the ed25519 signature"
        except ValueError as exc:
            return False, f"malformed ed25519 signature or key: {exc}"
        if not ok:
            return False, "signature does not match — record was altered or wrong key"
        pinned = os.environ.get(SIGNING_PUBLIC_ENV)
        if pinned and pinned.strip() != pub:
            return False, (f"signed by an unexpected key ({pub[:22]}…) — does not match "
                           f"the pinned {SIGNING_PUBLIC_ENV}")
        where = " (matches pinned key)" if pinned else ""
        return True, f"intact and ed25519 signature valid — signer {pub[:24]}…{where}"

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
