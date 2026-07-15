"""Criação do banco e de sessões SQLite."""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import Engine, create_engine, inspect
from sqlalchemy.orm import Session, sessionmaker

from bb_orchestrator.models import Base


def create_sqlite_engine(path: Path) -> Engine:
    path.parent.mkdir(parents=True, exist_ok=True)
    return create_engine(f"sqlite:///{path}")


def initialize_database(engine: Engine) -> None:
    Base.metadata.create_all(engine)
    _migrate_legacy_database(engine)


def _migrate_legacy_database(engine: Engine) -> None:
    """Aplica somente migrações aditivas necessárias para bancos locais antigos."""
    if engine.dialect.name != "sqlite":
        return

    with engine.begin() as connection:
        columns = {
            column["name"]
            for column in inspect(connection).get_columns("http_verification_attempts")
        }
        if "scheme" not in columns:
            connection.exec_driver_sql(
                "ALTER TABLE http_verification_attempts ADD COLUMN scheme VARCHAR(5)"
            )

        snapshot_sql = connection.exec_driver_sql(
            "SELECT sql FROM sqlite_master "
            "WHERE type = 'table' AND name = 'execution_policy_snapshots'"
        ).scalar_one_or_none()

    if snapshot_sql is None or "'katana'" in snapshot_sql:
        return

    with engine.connect() as connection:
        connection.exec_driver_sql("PRAGMA foreign_keys=OFF")
        connection.commit()
        try:
            with connection.begin():
                connection.exec_driver_sql(
                    """
                    CREATE TABLE execution_policy_snapshots_new (
                        id INTEGER NOT NULL PRIMARY KEY,
                        run_id INTEGER NOT NULL,
                        program_slug VARCHAR(64) NOT NULL,
                        step VARCHAR(16) NOT NULL,
                        snapshot JSON NOT NULL,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
                        CONSTRAINT ck_policy_snapshot_step
                            CHECK (step IN ('dns', 'http', 'ports', 'katana')),
                        FOREIGN KEY(run_id) REFERENCES runs (id),
                        FOREIGN KEY(program_slug) REFERENCES programs (slug)
                    )
                    """
                )
                connection.exec_driver_sql(
                    """
                    INSERT INTO execution_policy_snapshots_new
                        (id, run_id, program_slug, step, snapshot, created_at)
                    SELECT id, run_id, program_slug, step, snapshot, created_at
                    FROM execution_policy_snapshots
                    """
                )
                connection.exec_driver_sql("DROP TABLE execution_policy_snapshots")
                connection.exec_driver_sql(
                    "ALTER TABLE execution_policy_snapshots_new "
                    "RENAME TO execution_policy_snapshots"
                )
                connection.exec_driver_sql(
                    "CREATE INDEX ix_execution_policy_snapshots_run_id "
                    "ON execution_policy_snapshots (run_id)"
                )
                connection.exec_driver_sql(
                    "CREATE INDEX ix_execution_policy_snapshots_program_slug "
                    "ON execution_policy_snapshots (program_slug)"
                )
                connection.exec_driver_sql(
                    "CREATE INDEX ix_policy_snapshot_run_step "
                    "ON execution_policy_snapshots (run_id, step, id)"
                )
        finally:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            connection.commit()


def create_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)
