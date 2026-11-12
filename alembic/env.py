import os, sys
from alembic import context
from sqlalchemy import create_engine
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "backend"))
from platform_ext.db.base import Base
from platform_ext.db import models  # noqa: F401  (register tables)

url = os.environ["NB_DATABASE_URL"]
target_metadata = Base.metadata


def run_migrations_online():
    engine = create_engine(url)
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
