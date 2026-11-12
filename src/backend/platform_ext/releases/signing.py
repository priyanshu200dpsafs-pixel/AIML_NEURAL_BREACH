"""Release metadata signing/verification (Ed25519) with SHA-256 artifact digests.

Design note: this is a TUF-*inspired* targets-metadata check (signed, versioned, expiring metadata + trusted key IDs +
revocation + minimum-version policy). It is NOT a full TUF implementation (no root/snapshot/timestamp role chain, no
threshold signatures). For full rollback/freeze/key-compromise protection adopt python-tuf; see docs/SOFTWARE_UPDATE_BACKEND.md.
Private signing keys are never handled by this service; only public keys are configured.
"""
from __future__ import annotations
import base64, hashlib, json
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization


class SignatureError(Exception):
    pass


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def canonical(meta: Dict[str, Any]) -> bytes:
    return json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verify_signed_metadata(meta: Dict[str, Any], signature_b64: str, key_id: str,
                           trusted_keys: Dict[str, str], now: Optional[datetime] = None) -> None:
    pub_b64 = trusted_keys.get(key_id)
    if not pub_b64:
        raise SignatureError("untrusted key id")
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
        pub.verify(base64.b64decode(signature_b64), canonical(meta))
    except (InvalidSignature, ValueError) as e:
        raise SignatureError("invalid signature") from e
    exp = meta.get("expires")
    if not exp:
        raise SignatureError("metadata has no expiry")
    now = now or datetime.now(timezone.utc)
    if datetime.fromisoformat(exp.replace("Z", "+00:00")) <= now:
        raise SignatureError("metadata expired")


def check_artifact_binding(meta: Dict[str, Any], *, sha256: str, size: int, version: str, channel: str,
                           os_name: str, cpu_arch: str) -> None:
    """The signed metadata must describe exactly the row being registered (prevents substitution)."""
    want = {"sha256": sha256, "size": size, "version": version, "channel": channel, "os": os_name, "arch": cpu_arch}
    for k, v in want.items():
        if meta.get(k) != v:
            raise SignatureError(f"signed metadata mismatch on '{k}'")


def parse_version(v: str) -> Tuple[int, int, int]:
    try:
        a, b, c = v.split(".")
        return int(a), int(b), int(c)
    except Exception as e:
        raise ValueError(f"invalid semantic version: {v!r}") from e


# Test/tooling helpers only (never call in the service with real keys):
def generate_keypair_b64() -> Tuple[str, str]:
    sk = Ed25519PrivateKey.generate()
    priv = sk.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(priv).decode(), base64.b64encode(pub).decode()


def sign_metadata(meta: Dict[str, Any], private_b64: str) -> str:
    sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64))
    return base64.b64encode(sk.sign(canonical(meta))).decode()
