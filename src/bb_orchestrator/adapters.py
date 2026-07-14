"""Fronteira mockável e sem shell para subprocessos externos."""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Mapping, Sequence
from typing import Protocol


class SubprocessAdapter(Protocol):
    def find_executable(self, name: str) -> str | None: ...

    def run(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: int,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]: ...


class SystemSubprocessAdapter:
    """Executa somente listas de argumentos montadas pelo orquestrador."""

    def find_executable(self, name: str) -> str | None:
        return shutil.which(name)

    def run(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: int,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            capture_output=True,
            check=False,
            encoding="utf-8",
            env=dict(environment),
            errors="replace",
            stdin=subprocess.DEVNULL,
            shell=False,
            text=True,
            timeout=timeout_seconds,
        )


DEFAULT_SUBPROCESS_ADAPTER = SystemSubprocessAdapter()
