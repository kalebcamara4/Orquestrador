import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import inspect, select

from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.models import AssetModel
from bb_orchestrator.schemas import IngestRecord
from bb_orchestrator.services import import_scope_file, ingest_jsonl, list_queue, sanitize_run


@pytest.fixture
def session(tmp_path: Path):
    engine = create_sqlite_engine(tmp_path / "test.db")
    initialize_database(engine)
    with create_session_factory(engine)() as db_session:
        yield db_session


def test_database_contains_the_four_corresponding_tables(tmp_path: Path) -> None:
    engine = create_sqlite_engine(tmp_path / "tables.db")
    initialize_database(engine)
    assert set(inspect(engine).get_table_names()) == {
        "assets",
        "queue_items",
        "runs",
        "scope_rules",
    }


def test_ingest_filters_scope_deduplicates_and_sanitize_queues(tmp_path: Path, session) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n*.example.com\n", encoding="utf-8")
    import_scope_file(scope_file, session)

    input_file = tmp_path / "assets.jsonl"
    rows = [
        {"domain": "example.com"},
        {"domain": "API.EXAMPLE.COM."},
        {"domain": "api.example.com"},
        {"domain": "example.com.attacker.test"},
    ]
    input_file.write_text("".join(f"{json.dumps(row)}\n" for row in rows), encoding="utf-8")

    run = ingest_jsonl(input_file, session)

    assert (run.accepted_count, run.rejected_count, run.duplicate_count) == (2, 1, 1)
    assert list(session.scalars(select(AssetModel.domain).order_by(AssetModel.domain))) == [
        "api.example.com",
        "example.com",
    ]

    first = sanitize_run(run.id, session)
    second = sanitize_run(run.id, session)
    assert (first.sanitized, first.queued) == (2, 2)
    assert (second.sanitized, second.queued) == (0, 0)
    assert len(list_queue(session)) == 2


def test_ingest_schema_refuses_raw_or_sensitive_extra_fields() -> None:
    with pytest.raises(ValidationError):
        IngestRecord.model_validate(
            {"domain": "example.com", "headers": {"Authorization": "secret"}}
        )
