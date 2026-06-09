"""Name module registry."""

from __future__ import annotations

from osint_toolkit.core.module import BaseModule
from osint_toolkit.modules.name.github_search import GithubNameSearch


def all_name_modules() -> list[BaseModule]:
    return [GithubNameSearch()]


__all__ = ["GithubNameSearch", "all_name_modules"]
