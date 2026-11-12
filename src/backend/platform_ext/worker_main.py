"""Entry point: python -m src.backend.platform_ext.worker_main"""
import logging
from .config import get_settings
from .db.session import init_engine, session_scope  # noqa: F401
from .db import session as _sess
from .services.worker import load_adapter, worker_loop

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}')
    s = get_settings()
    init_engine(s.database_url)
    worker_loop(lambda: _sess._Session(), s, load_adapter(s.detection_adapter))
