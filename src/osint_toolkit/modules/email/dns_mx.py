"""DNS MX validation. Deliverability signal without sending mail."""

from __future__ import annotations

import dns.asyncresolver
import dns.resolver
import httpx

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


class DnsMx(BaseModule):
    @property
    def name(self) -> str:
        return "dns_mx"

    @property
    def category(self) -> str:
        return "email"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "dns"

    @property
    def rate_limit_per_min(self) -> int:
        return 600

    async def run(self, target: Target, client: httpx.AsyncClient) -> Finding:
        domain = target.value.split("@", 1)[1]
        try:
            answers = await dns.asyncresolver.resolve(domain, "MX")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.NOT_FOUND,
                confidence=Confidence.HIGH,
                data={"domain": domain},
            )
        except Exception as exc:  # noqa: BLE001
            return Finding(
                source=self.name,
                target_value=target.value,
                status=Status.ERROR,
                confidence=Confidence.LOW,
                error=f"{type(exc).__name__}: {exc}",
            )
        records = [
            {"priority": r.preference, "exchange": str(r.exchange.to_text()).rstrip(".")}
            for r in answers
        ]
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND,
            confidence=Confidence.HIGH,
            data={"domain": domain, "records": records, "deliverable_signal": True},
        )
