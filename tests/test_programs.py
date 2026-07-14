import json
from pathlib import Path

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

import bb_orchestrator.cli as cli
from bb_orchestrator.cli import app
from bb_orchestrator.database import create_session_factory, create_sqlite_engine
from bb_orchestrator.models import ScopeRuleModel
from bb_orchestrator.programs import (
    CURRENT_PROGRAM_PATH,
    NO_ACTIVE_PROGRAM_MESSAGE,
    ProgramError,
    archive_program,
    create_program,
    current_program_slug,
    list_programs,
    load_program,
    select_program,
)


@pytest.fixture(autouse=True)
def isolated_workspace(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def test_create_builds_isolated_tree_and_can_select_program() -> None:
    runner = CliRunner()

    result = runner.invoke(
        app,
        ["program", "create", "acme", "--name", "Acme Bug Bounty"],
        input="y\n",
    )

    assert result.exit_code == 0, result.output
    assert "Deseja selecionar" in result.output
    assert Path(".bb/programs/acme/orchestrator.db").is_file()
    assert Path(".bb/programs/acme/runs").is_dir()
    assert json.loads(CURRENT_PROGRAM_PATH.read_text(encoding="utf-8")) == {"slug": "acme"}
    assert current_program_slug() == "acme"


def test_create_can_leave_current_selection_unchanged() -> None:
    result = CliRunner().invoke(
        app,
        ["program", "create", "acme", "--name", "Acme"],
        input="n\n",
    )

    assert result.exit_code == 0, result.output
    assert current_program_slug() is None


@pytest.mark.parametrize("slug", ["Acme", "acme_test", "../acme", "-acme", "acme-"])
def test_create_rejects_unsafe_slugs(slug: str) -> None:
    with pytest.raises(ProgramError, match="slug inválido"):
        create_program(slug, "Acme")


def test_program_list_and_show_report_active_database_and_archive_state() -> None:
    create_program("alpha", "Alpha")
    create_program("beta", "Beta")
    select_program("alpha")
    archive_program("beta")
    runner = CliRunner()

    listed = runner.invoke(app, ["program", "list"])
    shown = runner.invoke(app, ["program", "show"])

    assert listed.exit_code == shown.exit_code == 0
    assert "*  alpha  Alpha  active" in listed.output
    assert "beta  Beta  archived" in listed.output
    assert "Program: alpha" in shown.output
    assert "Database: .bb/programs/alpha/orchestrator.db" in shown.output


def test_select_slug_is_non_interactive_and_refuses_archived_program() -> None:
    create_program("alpha", "Alpha")
    create_program("old", "Old")
    archive_program("old")
    runner = CliRunner()

    selected = runner.invoke(app, ["program", "select", "alpha"])
    archived = runner.invoke(app, ["program", "select", "old"])

    assert selected.exit_code == 0, selected.output
    assert current_program_slug() == "alpha"
    assert archived.exit_code == 1
    assert "arquivado não pode ser selecionado" in archived.output


def test_select_without_slug_uses_questionary_and_hides_archived(monkeypatch) -> None:
    create_program("alpha", "Alpha")
    create_program("beta", "Beta")
    create_program("old", "Old")
    archive_program("old")
    captured = {}

    class FakeQuestion:
        def ask(self):
            return "beta"

    def fake_select(message, *, choices, **kwargs):
        captured["message"] = message
        captured["choices"] = choices
        captured["kwargs"] = kwargs
        return FakeQuestion()

    monkeypatch.setattr(cli.questionary, "select", fake_select)

    result = CliRunner().invoke(app, ["program", "select"])

    assert result.exit_code == 0, result.output
    assert current_program_slug() == "beta"
    assert captured["message"] == "Selecione o programa:"
    assert [choice.value for choice in captured["choices"]] == ["alpha", "beta"]
    assert all(choice.value != "old" for choice in captured["choices"])


def test_archive_preserves_database_and_artifacts_and_clears_active_selection() -> None:
    program = create_program("acme", "Acme")
    select_program("acme")
    artifact = program.runs_path / "keep.txt"
    artifact.write_text("preservar", encoding="utf-8")
    database_bytes_before = program.database_path.read_bytes()

    result = CliRunner().invoke(app, ["program", "archive", "acme"])

    assert result.exit_code == 0, result.output
    assert program.database_path.is_file()
    assert artifact.read_text(encoding="utf-8") == "preservar"
    assert len(program.database_path.read_bytes()) >= len(database_bytes_before)
    assert load_program("acme").archived
    assert current_program_slug() is None


def test_commands_fail_with_required_message_without_active_program(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("BB_DB_PATH", str(tmp_path / "legacy.db"))
    Path("scope.txt").write_text("*.example.com\n", encoding="utf-8")
    Path("assets.jsonl").write_text('{"domain":"api.example.com"}\n', encoding="utf-8")
    runner = CliRunner()
    commands = [
        ["scope", "import", "scope.txt"],
        ["run", "ingest", "assets.jsonl"],
        ["recon", "passive", "--dry-run"],
        ["candidates", "list", "1"],
        ["candidates", "approve", "1", "--all"],
        ["candidates", "reject", "1", "--host", "api.example.com"],
        ["assets", "export", "1"],
        ["assets", "list", "1"],
        ["verify", "dns", "1", "--dry-run"],
        ["sanitize", "1"],
        ["triage", "1", "--dry-run"],
        ["queue", "list"],
    ]
    results = [runner.invoke(app, command) for command in commands]
    shown = runner.invoke(app, ["program", "show"])

    assert all(result.exit_code == 1 for result in results)
    assert all(result.output.strip() == NO_ACTIVE_PROGRAM_MESSAGE for result in results)
    assert shown.exit_code == 1
    assert shown.output.strip() == NO_ACTIVE_PROGRAM_MESSAGE
    assert not (tmp_path / "legacy.db").exists()


def test_program_databases_and_run_artifacts_are_isolated() -> None:
    alpha = create_program("alpha", "Alpha")
    beta = create_program("beta", "Beta")
    Path("alpha-scope.txt").write_text("*.alpha.test\n", encoding="utf-8")
    Path("beta-scope.txt").write_text("*.beta.test\n", encoding="utf-8")
    Path("alpha.jsonl").write_text('{"domain":"api.alpha.test"}\n', encoding="utf-8")
    Path("beta.jsonl").write_text('{"domain":"api.beta.test"}\n', encoding="utf-8")
    runner = CliRunner()

    select_program("alpha")
    alpha_scope = runner.invoke(app, ["scope", "import", "alpha-scope.txt"])
    assert runner.invoke(app, ["run", "ingest", "alpha.jsonl"]).exit_code == 0
    assert runner.invoke(app, ["candidates", "approve", "1", "--all"]).exit_code == 0
    assert runner.invoke(app, ["assets", "export", "1"]).exit_code == 0

    select_program("beta")
    beta_scope = runner.invoke(app, ["scope", "import", "beta-scope.txt"])
    assert runner.invoke(app, ["run", "ingest", "beta.jsonl"]).exit_code == 0
    assert runner.invoke(app, ["candidates", "approve", "1", "--all"]).exit_code == 0
    assert runner.invoke(app, ["assets", "export", "1"]).exit_code == 0

    assert "Program: alpha" in alpha_scope.output
    assert "Program: beta" in beta_scope.output
    assert (alpha.runs_path / "1/assets.jsonl").read_text(encoding="utf-8") == (
        '{"domain":"api.alpha.test"}\n'
    )
    assert (beta.runs_path / "1/assets.jsonl").read_text(encoding="utf-8") == (
        '{"domain":"api.beta.test"}\n'
    )

    alpha_engine = create_sqlite_engine(alpha.database_path)
    beta_engine = create_sqlite_engine(beta.database_path)
    with create_session_factory(alpha_engine)() as session:
        assert list(session.scalars(select(ScopeRuleModel.pattern))) == ["*.alpha.test"]
    with create_session_factory(beta_engine)() as session:
        assert list(session.scalars(select(ScopeRuleModel.pattern))) == ["*.beta.test"]


def test_list_programs_is_sorted_and_can_exclude_archived() -> None:
    create_program("zeta", "Zeta")
    create_program("alpha", "Alpha")
    archive_program("zeta")

    assert [program.slug for program in list_programs()] == ["alpha", "zeta"]
    assert [program.slug for program in list_programs(include_archived=False)] == ["alpha"]
