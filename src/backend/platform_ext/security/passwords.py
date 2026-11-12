"""Password hashing: argon2id (argon2-cffi) when installed, scrypt (stdlib, memory-hard) as fallback."""
from __future__ import annotations
import base64, hashlib, hmac, os

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import InvalidHashError, VerifyMismatchError
    _ph = PasswordHasher()
except ImportError:  # pragma: no cover
    _ph = None

MIN_LEN = 12
_N, _R, _P = 2 ** 15, 8, 1


def validate_password_policy(pw: str) -> None:
    if len(pw) < MIN_LEN:
        raise ValueError(f"Password must be at least {MIN_LEN} characters")
    if len(pw) > 256:
        raise ValueError("Password too long")


def hash_password(pw: str) -> str:
    if _ph is not None:
        return _ph.hash(pw)
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, n=_N, r=_R, p=_P, maxmem=64 * 1024 * 1024, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    try:
        if stored.startswith("scrypt$"):
            _, s, d = stored.split("$")
            dk = hashlib.scrypt(pw.encode(), salt=base64.b64decode(s), n=_N, r=_R, p=_P,
                                maxmem=64 * 1024 * 1024, dklen=32)
            return hmac.compare_digest(dk, base64.b64decode(d))
        if _ph is not None:
            return _ph.verify(stored, pw)
    except Exception:
        return False
    return False


# Used to equalise timing when the account does not exist.
DUMMY_HASH = hash_password("dummy-password-for-timing")
