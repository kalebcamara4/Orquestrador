import pytest

from bb_orchestrator.terminal_ui import (
    ChecklistItem,
    SelectionCancelled,
    select_checkboxes,
)


def _reader(keys: list[str]):
    iterator = iter(keys)
    return lambda: next(iterator)


def _items() -> list[ChecklistItem]:
    return [
        ChecklistItem(value="api.example.com", label="api.example.com"),
        ChecklistItem(value="dev.example.com", label="dev.example.com"),
        ChecklistItem(value="old.example.com", label="old.example.com"),
    ]


def test_checklist_supports_arrows_space_select_all_and_deselect_all() -> None:
    output: list[str] = []
    keys = [
        " ",
        "\x1b",
        "[",
        "B",
        " ",
        "n",
        "a",
        "\x1b",
        "[",
        "A",
        " ",
        "\r",
    ]

    selected = select_checkboxes(
        "Escolha",
        _items(),
        reader=_reader(keys),
        writer=output.append,
    )

    assert selected == ["dev.example.com", "old.example.com"]
    assert any("a: todos | n: nenhum" in line for line in output)
    assert any("[x] api.example.com" in line for line in output)


def test_checklist_refuses_empty_confirmation_until_an_item_is_selected() -> None:
    output: list[str] = []

    selected = select_checkboxes(
        "Escolha",
        _items(),
        reader=_reader(["\r", " ", "\r"]),
        writer=output.append,
    )

    assert selected == ["api.example.com"]
    assert "Selecione ao menos um candidato." in output


def test_checklist_can_be_cancelled_without_selection() -> None:
    with pytest.raises(SelectionCancelled):
        select_checkboxes(
            "Escolha",
            _items(),
            reader=_reader(["q"]),
            writer=lambda line: None,
        )


def test_empty_checklist_returns_without_reading_keyboard() -> None:
    selected = select_checkboxes(
        "Escolha",
        [],
        reader=lambda: pytest.fail("checklist vazio tentou ler o teclado"),
    )

    assert selected == []
