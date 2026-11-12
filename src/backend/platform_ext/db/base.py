from datetime import datetime, timezone
from sqlalchemy.orm import DeclarativeBase


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


def as_utc(dt):
    """SQLite drops tzinfo; PostgreSQL keeps it. Normalise so comparisons work on both."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt
