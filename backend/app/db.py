"""SQLite connection setup.

storage.py imports SessionLocal, main.py imports init_db.
"""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

from app.models import Base

# backend/secret_timeline.db - the same file no matter which folder uvicorn is started from
DB_PATH = Path(__file__).resolve().parent.parent / "secret_timeline.db"

engine = create_engine(
    URL.create("sqlite", database=str(DB_PATH)),
    # FastAPI runs sync routes in a thread pool, so SQLite must allow cross-thread use
    connect_args={"check_same_thread": False},
)

SessionLocal = sessionmaker(bind=engine)


def init_db() -> None:
    """Create the commits and findings tables if they don't exist yet."""
    Base.metadata.create_all(bind=engine)