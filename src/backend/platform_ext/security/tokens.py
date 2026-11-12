"""Access JWTs (short-lived, HS256), opaque refresh tokens (hashed at rest), device secrets, enrollment tokens, WS tickets."""
from __future__ import annotations
import hashlib, hmac, secrets, time
from typing import Any, Dict, Optional, Tuple
import jwt  # PyJWT


class TokenError(Exception):
    pass


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def new_opaque_token(nbytes: int = 48) -> Tuple[str, str]:
    """Returns (plaintext, sha256_hex). Plaintext is shown to the caller once and never stored."""
    t = secrets.token_urlsafe(nbytes)
    return t, sha256_hex(t)


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def encode_jwt(claims: Dict[str, Any], *, secret: str, issuer: str, audience: str, ttl: int,
               typ: str, now: Optional[float] = None) -> str:
    now = int(now if now is not None else time.time())
    body = {**claims, "iss": issuer, "aud": audience, "iat": now, "nbf": now, "exp": now + ttl, "typ": typ,
            "jti": secrets.token_hex(8)}
    return jwt.encode(body, secret, algorithm="HS256")


def decode_jwt(token: str, *, secret: str, issuer: str, audience: str, typ: str,
               now: Optional[float] = None) -> Dict[str, Any]:
    try:
        opts = {"require": ["exp", "iat", "iss", "aud", "typ"]}
        # PyJWT checks exp against wall-clock; for tests we allow an injected clock via leeway-free manual check.
        claims = jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, audience=audience,
                            options={**opts, "verify_exp": now is None})
    except jwt.PyJWTError as e:
        raise TokenError(str(e)) from e
    if now is not None and claims["exp"] <= now:
        raise TokenError("expired")
    if claims.get("typ") != typ:
        raise TokenError("wrong token type")
    return claims


# Device credentials: "<device_id>.<secret>"; server stores only sha256(secret).
def make_device_bearer(device_id: str, secret: str) -> str:
    return f"{device_id}.{secret}"


def parse_device_bearer(value: str) -> Tuple[str, str]:
    if "." not in value:
        raise TokenError("malformed device credential")
    did, sec = value.split(".", 1)
    if not did or not sec or len(did) != 36:
        raise TokenError("malformed device credential")
    return did, sec
