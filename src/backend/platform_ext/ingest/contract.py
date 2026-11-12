"""Validation against the frozen Role 3 feature contract (feature_columns.json). Never mutates or extends the contract."""
from __future__ import annotations
import hashlib, json, math
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Sequence


class ContractError(ValueError):
    def __init__(self, msg: str, index: Optional[int] = None):
        super().__init__(msg)
        self.index = index


def load_feature_columns(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        for k in ("feature_columns", "features", "columns"):
            if k in data:
                data = data[k]
                break
    if not isinstance(data, list) or not all(isinstance(x, str) for x in data):
        raise ValueError("Unrecognised feature_columns.json format")
    if len(set(data)) != len(data):
        raise ValueError("Duplicate feature names in contract")
    return data


def contract_fingerprint(columns: Sequence[str]) -> str:
    return hashlib.sha256(json.dumps(list(columns)).encode()).hexdigest()


def parse_timestamp(value: Any, *, now: Optional[datetime] = None, max_skew_seconds: int = 86400) -> datetime:
    if not isinstance(value, str):
        raise ContractError("observed_at must be an ISO-8601 string")
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise ContractError("observed_at is not valid ISO-8601") from e
    if ts.tzinfo is None:
        raise ContractError("observed_at must include a timezone")
    now = now or datetime.now(timezone.utc)
    if abs((ts - now).total_seconds()) > max_skew_seconds:
        raise ContractError("observed_at outside allowed clock-skew window")
    return ts.astimezone(timezone.utc)


def validate_features(features: Any, columns: Sequence[str], index: Optional[int] = None) -> Dict[str, float]:
    if not isinstance(features, dict):
        raise ContractError("features must be an object", index)
    expected = set(columns)
    got = set(features.keys())
    missing, extra = expected - got, got - expected
    if missing:
        raise ContractError(f"missing {len(missing)} feature(s): {sorted(missing)[:5]}", index)
    if extra:
        raise ContractError(f"unexpected feature(s) (payload/extra fields not accepted): {sorted(extra)[:5]}", index)
    out: Dict[str, float] = {}
    for k in columns:
        v = features[k]
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            raise ContractError(f"feature '{k}' must be numeric", index)
        if not math.isfinite(v):
            raise ContractError(f"feature '{k}' must be finite", index)
        out[k] = float(v)
    return out


def validate_batch(flows: Any, columns: Sequence[str], *, max_flows: int, max_skew_seconds: int,
                   now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    if not isinstance(flows, list) or not flows:
        raise ContractError("flows must be a non-empty list")
    if len(flows) > max_flows:
        raise ContractError(f"batch exceeds {max_flows} flows")
    clean = []
    for i, fl in enumerate(flows):
        if not isinstance(fl, dict) or set(fl.keys()) - {"observed_at", "features"}:
            raise ContractError("each flow must contain only 'observed_at' and 'features'", i)
        ts = parse_timestamp(fl.get("observed_at"), now=now, max_skew_seconds=max_skew_seconds)
        clean.append({"observed_at": ts, "features": validate_features(fl.get("features"), columns, i)})
    return clean
