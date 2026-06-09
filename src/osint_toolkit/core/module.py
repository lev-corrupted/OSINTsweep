"""BaseModule ABC — every source plugs in here."""

from __future__ import annotations

from abc import ABC, abstractmethod

import httpx

from osint_toolkit.core.models import Finding, Target


class BaseModule(ABC):
    """Subclass this for every new source. Tests live in tests/modules/<category>/test_<name>.py."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable, lowercase, kebab-or-underscore. Appears in CLI output + JSON."""

    @property
    @abstractmethod
    def category(self) -> str:
        """One of: email, username, name, domain. Dispatcher uses this to match the Target.kind."""

    @property
    @abstractmethod
    def modes_allowed(self) -> set[str]:
        """Subset of {'prospect', 'selfcheck', 'pentest'}. Dispatcher refuses to run otherwise."""

    @property
    @abstractmethod
    def host(self) -> str:
        """The hostname this module talks to. Used for per-host rate limiting."""

    @property
    def requires_api_key(self) -> bool:
        return False

    @property
    def rate_limit_per_min(self) -> int:
        return 60

    @abstractmethod
    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        """The actual work. Return a Finding. Raise on transport errors; the dispatcher will catch."""
