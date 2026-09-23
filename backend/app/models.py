from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class Commit(Base):
    __tablename__ = "commits"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_url = Column(String, nullable=False, index=True)
    scan_id = Column(String, nullable=False, index=True)
    commit_hash = Column(String, nullable=False)
    commit_date = Column(String, nullable=False)
    author = Column(String, nullable=False)
    message = Column(String, nullable=True)
    has_secret = Column(Boolean, default=False)


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    repo_url = Column(String, nullable=False, index=True)
    scan_id = Column(String, nullable=False, index=True)
    secret_type = Column(String, nullable=False)
    secret_hash = Column(String, nullable=False, index=True)
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    commit_hash = Column(String, nullable=False)
    commit_date = Column(String, nullable=False)
    author = Column(String, nullable=False)
    detected_by = Column(String, nullable=False)
    still_present = Column(Boolean, default=False)
    is_live = Column(Boolean, nullable=True)
    created_at = Column(DateTime, nullable=True)