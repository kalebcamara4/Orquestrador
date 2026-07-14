"""Componentes interativos de terminal sem dependências externas."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

import typer


class SelectionCancelled(Exception):
    """Indica que o usuário cancelou um checklist sem aplicar alterações."""


@dataclass(frozen=True)
class ChecklistItem:
    value: str
    label: str


KeyReader = Callable[[], str]
Writer = Callable[[str], None]


def _terminal_key(reader: KeyReader) -> str:
    key = reader()
    if key in ("\x1b[A", "\x00H", "\xe0H"):
        return "up"
    if key in ("\x1b[B", "\x00P", "\xe0P"):
        return "down"
    if key == "\x1b":
        second = reader()
        if second in ("[", "O"):
            third = reader()
            if third == "A":
                return "up"
            if third == "B":
                return "down"
        return "unknown"
    if key in ("k", "K"):
        return "up"
    if key in ("j", "J"):
        return "down"
    if key == " ":
        return "toggle"
    if key in ("a", "A"):
        return "all"
    if key in ("n", "N"):
        return "none"
    if key in ("\r", "\n"):
        return "confirm"
    if key in ("q", "Q"):
        return "cancel"
    return "unknown"


def _render_checklist(
    title: str,
    items: Sequence[ChecklistItem],
    selected: set[int],
    cursor: int,
    message: str | None,
    writer: Writer,
) -> None:
    writer("\033[2J\033[H")
    writer(title)
    writer("Setas: mover | Espaço: marcar | a: todos | n: nenhum | Enter: confirmar | q: cancelar")
    writer("")
    for index, item in enumerate(items):
        pointer = ">" if index == cursor else " "
        checkbox = "[x]" if index in selected else "[ ]"
        writer(f"{pointer} {checkbox} {item.label}")
    if message:
        writer("")
        writer(message)


def select_checkboxes(
    title: str,
    items: Sequence[ChecklistItem],
    *,
    reader: KeyReader | None = None,
    writer: Writer | None = None,
) -> list[str]:
    """Seleciona valores usando setas/espaço, com atalhos para todos e nenhum."""
    if not items:
        return []

    read_key = reader or (lambda: typer.getchar(echo=False))
    write_line = writer or typer.echo
    selected: set[int] = set()
    cursor = 0
    message: str | None = None

    while True:
        _render_checklist(title, items, selected, cursor, message, write_line)
        action = _terminal_key(read_key)
        message = None

        if action == "up":
            cursor = (cursor - 1) % len(items)
        elif action == "down":
            cursor = (cursor + 1) % len(items)
        elif action == "toggle":
            if cursor in selected:
                selected.remove(cursor)
            else:
                selected.add(cursor)
        elif action == "all":
            selected = set(range(len(items)))
        elif action == "none":
            selected.clear()
        elif action == "confirm":
            if not selected:
                message = "Selecione ao menos um candidato."
                continue
            return [item.value for index, item in enumerate(items) if index in selected]
        elif action == "cancel":
            raise SelectionCancelled
