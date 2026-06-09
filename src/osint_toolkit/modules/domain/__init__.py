"""Domain module registry."""

from __future__ import annotations

from osint_toolkit.core.module import BaseModule
from osint_toolkit.modules.domain.dns_records import DnsRecords
from osint_toolkit.modules.domain.whois_lookup import WhoisLookup


def all_domain_modules() -> list[BaseModule]:
    return [DnsRecords(), WhoisLookup()]


__all__ = ["DnsRecords", "WhoisLookup", "all_domain_modules"]
