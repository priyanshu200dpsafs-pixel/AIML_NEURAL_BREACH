from __future__ import annotations
from contextlib import contextmanager
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

_engine = None
_Session = None


def init_engine(url: str, **kw):
    global _engine, _Session
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
        _engine = None
        _Session = None
    if url.startswith("sqlite"):
        kw.setdefault("connect_args", {"check_same_thread": False})
    else:
        kw.setdefault("pool_size", 10)
        kw.setdefault("max_overflow", 10)
        kw.setdefault("pool_timeout", 10)
        kw.setdefault("pool_recycle", 1800)
    _engine = create_engine(url, pool_pre_ping=True, future=True, **kw)
    _Session = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False, future=True)
    return _engine


def get_engine():
    if _engine is None:
        raise RuntimeError("init_engine() has not been called")
    return _engine


@contextmanager
def session_scope():
    s: Session = _Session()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def get_db():
    """FastAPI dependency: one transaction per request."""
    with session_scope() as s:
        yield s
