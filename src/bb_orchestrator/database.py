"""Criação do banco e de sessões SQLite."""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from bb_orchestrator.models import Base

DEFAULT_DB_PATH = Path(".bb/orchestrator.db")


def database_path() -> Path:
    configured_path = os.environ.get("BB_DB_PATH")
    return Path(configured_path).expanduser() if configured_path else DEFAULT_DB_PATH


def create_sqlite_engine(path: Path | None = None) -> Engine:
    db_path = path or database_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{db_path}")


def initialize_database(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    candidate_columns = {column["name"] for column in inspect(engine).get_columns("candidates")}
    if "deleted_at" not in candidate_columns:
        with engine.begin() as connection:
            connection.exec_driver_sql("ALTER TABLE candidates ADD COLUMN deleted_at DATETIME")


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
