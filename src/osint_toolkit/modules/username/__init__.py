"""Username module registry."""

from __future__ import annotations

from osint_toolkit.core.module import BaseModule
from osint_toolkit.modules.username.sherlock_style import UsernameSite, load_username_sites


def all_username_modules() -> list[BaseModule]:
    return list(load_username_sites())


__all__ = ["UsernameSite", "load_username_sites", "all_username_modules"]
