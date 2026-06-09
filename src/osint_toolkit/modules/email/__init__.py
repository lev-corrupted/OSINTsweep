"""Email module registry."""

from __future__ import annotations

from osint_toolkit.core.module import BaseModule
from osint_toolkit.modules.email.dns_mx import DnsMx
from osint_toolkit.modules.email.gravatar import Gravatar
from osint_toolkit.modules.email.holehe_check import HolehSite, load_holehe_sites


def all_email_modules() -> list[BaseModule]:
    mods: list[BaseModule] = [Gravatar(), DnsMx()]
    mods.extend(load_holehe_sites())
    return mods


__all__ = ["Gravatar", "DnsMx", "HolehSite", "load_holehe_sites", "all_email_modules"]
