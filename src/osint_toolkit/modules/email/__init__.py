"""Email module registry."""

from __future__ import annotations

from osint_toolkit.core.module import BaseModule
from osint_toolkit.modules.email.dns_mx import DnsMx
from osint_toolkit.modules.email.emailrep import EmailRep
from osint_toolkit.modules.email.gravatar import Gravatar
from osint_toolkit.modules.email.holehe_check import HolehSite, load_holehe_sites
from osint_toolkit.modules.email.hunter_pattern import HunterPattern


def all_email_modules() -> list[BaseModule]:
    mods: list[BaseModule] = [Gravatar(), DnsMx(), HunterPattern(), EmailRep()]
    mods.extend(load_holehe_sites())
    return mods


__all__ = [
    "EmailRep",
    "Gravatar",
    "DnsMx",
    "HolehSite",
    "HunterPattern",
    "load_holehe_sites",
    "all_email_modules",
]
