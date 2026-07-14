"""Ciclo de vida e seleção de programas isolados no filesystem local."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError

from bb_orchestrator.database import (
    create_session_factory,
    create_sqlite_engine,
    initialize_database,
)
from bb_orchestrator.models import ProgramModel, ProgramPolicyModel
from bb_orchestrator.policies import DEFAULT_POLICY_NAME

STATE_ROOT = Path(".bb")
PROGRAMS_ROOT = STATE_ROOT / "programs"
CURRENT_PROGRAM_PATH = STATE_ROOT / "current-program.json"
NO_ACTIVE_PROGRAM_MESSAGE = "Nenhum programa selecionado. Execute: bb program select"

_SLUG_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$")


class ProgramError(ValueError):
    """Erro seguro e apresentável de gerenciamento de programas."""


@dataclass(frozen=True)
class ProgramInfo:
    slug: str
    name: str
    created_at: datetime
    archived_at: datetime | None
    database_path: Path
    runs_path: Path

    @property
    def archived(self) -> bool:
        return self.archived_at is not None


def validate_slug(slug: str) -> str:
    if not isinstance(slug, str) or not _SLUG_PATTERN.fullmatch(slug):
        raise ProgramError("slug inválido; use 1 a 64 caracteres minúsculos, números e hífens")
    return slug


def validate_name(name: str) -> str:
    if not isinstance(name, str):
        raise ProgramError("o nome do programa deve ser texto")
    normalized = name.strip()
    if not normalized or len(normalized) > 160 or any(char in normalized for char in "\r\n\0"):
        raise ProgramError("o nome deve ter entre 1 e 160 caracteres e ocupar uma linha")
    return normalized


def _program_directory(slug: str) -> Path:
    return PROGRAMS_ROOT / validate_slug(slug)


def program_database_path(slug: str) -> Path:
    return _program_directory(slug) / "orchestrator.db"


def program_runs_path(slug: str) -> Path:
    return _program_directory(slug) / "runs"


def _model_to_info(model: ProgramModel) -> ProgramInfo:
    return ProgramInfo(
        slug=model.slug,
        name=model.name,
        created_at=model.created_at,
        archived_at=model.archived_at,
        database_path=program_database_path(model.slug),
        runs_path=program_runs_path(model.slug),
    )


def load_program(slug: str) -> ProgramInfo:
    normalized_slug = validate_slug(slug)
    program_directory = _program_directory(normalized_slug)
    database_path = program_database_path(normalized_slug)
    runs_path = program_runs_path(normalized_slug)
    if (
        program_directory.is_symlink()
        or database_path.is_symlink()
        or runs_path.is_symlink()
        or not database_path.is_file()
        or not runs_path.is_dir()
    ):
        raise ProgramError(f"programa não encontrado: {normalized_slug}")

    engine = create_sqlite_engine(database_path)
    try:
        with create_session_factory(engine)() as session:
            model = session.scalar(select(ProgramModel).where(ProgramModel.slug == normalized_slug))
    except SQLAlchemyError as exc:
        raise ProgramError(f"banco inválido para o programa: {normalized_slug}") from exc
    finally:
        engine.dispose()
    if model is None:
        raise ProgramError(f"metadados ausentes para o programa: {normalized_slug}")
    return _model_to_info(model)


def create_program(slug: str, name: str) -> ProgramInfo:
    normalized_slug = validate_slug(slug)
    normalized_name = validate_name(name)
    program_directory = _program_directory(normalized_slug)
    if program_directory.exists():
        raise ProgramError(f"programa já existe: {normalized_slug}")

    runs_path = program_runs_path(normalized_slug)
    try:
        runs_path.mkdir(parents=True, exist_ok=False)
    except OSError as exc:
        raise ProgramError(f"não foi possível criar o programa: {exc}") from exc

    database_path = program_database_path(normalized_slug)
    engine = create_sqlite_engine(database_path)
    try:
        initialize_database(engine)
        with create_session_factory(engine)() as session:
            model = ProgramModel(slug=normalized_slug, name=normalized_name)
            session.add(model)
            session.flush()
            session.add(
                ProgramPolicyModel(
                    program_slug=normalized_slug,
                    policy_name=DEFAULT_POLICY_NAME.value,
                )
            )
            session.commit()
            session.refresh(model)
            return _model_to_info(model)
    except (OSError, SQLAlchemyError) as exc:
        raise ProgramError(f"não foi possível inicializar o programa: {exc}") from exc
    finally:
        engine.dispose()


def list_programs(*, include_archived: bool = True) -> list[ProgramInfo]:
    if not PROGRAMS_ROOT.is_dir():
        return []

    programs: list[ProgramInfo] = []
    for directory in sorted(PROGRAMS_ROOT.iterdir(), key=lambda path: path.name):
        if (
            directory.is_symlink()
            or not directory.is_dir()
            or not _SLUG_PATTERN.fullmatch(directory.name)
        ):
            continue
        try:
            program = load_program(directory.name)
        except ProgramError:
            continue
        if include_archived or not program.archived:
            programs.append(program)
    return programs


def current_program_slug() -> str | None:
    if not CURRENT_PROGRAM_PATH.is_file():
        return None
    try:
        payload = json.loads(CURRENT_PROGRAM_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProgramError("arquivo current-program.json inválido") from exc
    if not isinstance(payload, dict) or set(payload) != {"slug"}:
        raise ProgramError("arquivo current-program.json inválido")
    try:
        return validate_slug(payload["slug"])
    except (ProgramError, TypeError) as exc:
        raise ProgramError("arquivo current-program.json inválido") from exc


def _write_current_program(slug: str) -> None:
    content = json.dumps({"slug": slug}, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    temporary_path = CURRENT_PROGRAM_PATH.with_suffix(".json.tmp")
    try:
        CURRENT_PROGRAM_PATH.parent.mkdir(parents=True, exist_ok=True)
        try:
            temporary_path.write_text(content, encoding="utf-8")
            temporary_path.replace(CURRENT_PROGRAM_PATH)
        finally:
            temporary_path.unlink(missing_ok=True)
    except OSError as exc:
        raise ProgramError(f"não foi possível selecionar o programa: {exc}") from exc


def select_program(slug: str) -> ProgramInfo:
    program = load_program(slug)
    if program.archived:
        raise ProgramError(f"programa arquivado não pode ser selecionado: {program.slug}")
    _write_current_program(program.slug)
    return program


def require_active_program() -> ProgramInfo:
    slug = current_program_slug()
    if slug is None:
        raise ProgramError(NO_ACTIVE_PROGRAM_MESSAGE)
    try:
        program = load_program(slug)
    except ProgramError as exc:
        raise ProgramError(NO_ACTIVE_PROGRAM_MESSAGE) from exc
    if program.archived:
        raise ProgramError(NO_ACTIVE_PROGRAM_MESSAGE)
    return program


def archive_program(slug: str) -> ProgramInfo:
    program = load_program(slug)
    engine = create_sqlite_engine(program.database_path)
    try:
        with create_session_factory(engine)() as session:
            model = session.scalar(select(ProgramModel).where(ProgramModel.slug == program.slug))
            if model is None:
                raise ProgramError(f"metadados ausentes para o programa: {program.slug}")
            if model.archived_at is None:
                model.archived_at = datetime.now(UTC)
                session.commit()
            session.refresh(model)
            archived = _model_to_info(model)
    except SQLAlchemyError as exc:
        raise ProgramError(f"não foi possível arquivar o programa: {program.slug}") from exc
    finally:
        engine.dispose()

    if current_program_slug() == program.slug:
        try:
            CURRENT_PROGRAM_PATH.unlink(missing_ok=True)
        except OSError as exc:
            raise ProgramError("programa arquivado, mas não foi possível limpar a seleção") from exc
    return archived
