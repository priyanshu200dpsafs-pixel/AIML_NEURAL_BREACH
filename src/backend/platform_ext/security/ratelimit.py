"""In-process token bucket. Correct for a single API process; behind multiple replicas put a shared limiter
(reverse proxy or Redis) in front -- documented limitation."""
from __future__ import annotations
import threading, time
from typing import Dict, Optional, Tuple


class RateLimiter:
    def __init__(self, max_keys: int = 50_000):
        self._b: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
        self._max = max_keys

    def allow(self, key: str, per_minute: int, burst: Optional[int] = None, now: Optional[float] = None) -> bool:
        now = time.monotonic() if now is None else now
        cap = float(burst or per_minute)
        rate = per_minute / 60.0
        with self._lock:
            tokens, last = self._b.get(key, (cap, now))
            tokens = min(cap, tokens + (now - last) * rate)
            ok = tokens >= 1.0
            if ok:
                tokens -= 1.0
            if len(self._b) >= self._max and key not in self._b:
                self._b.pop(next(iter(self._b)))   # bound memory under key-flood attacks
            self._b[key] = (tokens, now)
            return ok
