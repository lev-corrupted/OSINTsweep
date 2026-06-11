"""Username permutator — generate plausible handles from a real name.

Given "Vishesh Bhatia", produces: vishesh.bhatia, vbhatia, bhatia.vishesh,
v.bhatia, vishesh_bhatia, vishesh, vbhatia_bkk (if hint=bkk), etc.

These are then fed back through the username pipeline to discover platforms.
"""

from __future__ import annotations

from osint_toolkit.core.models import Confidence, Finding, Status, Target
from osint_toolkit.core.module import BaseModule


def permutations(name: str, hint: str = "") -> list[str]:
    parts = [p.strip().lower() for p in name.split() if p.strip()]
    parts = [p for p in parts if p not in {"dr", "dr.", "mr", "mr.", "mrs", "mrs.", "prof", "prof.", "professor"}]
    if not parts:
        return []
    first = parts[0]
    last = parts[-1]
    out: set[str] = set()
    # Single-component (e.g., only "Linus" or "Bhatia")
    out.add(first)
    if last != first:
        out.add(last)
    # First+last combos
    if last != first:
        out.update(
            {
                f"{first}{last}",
                f"{first}.{last}",
                f"{first}_{last}",
                f"{first}-{last}",
                f"{first[0]}{last}",
                f"{first[0]}.{last}",
                f"{last}{first[0]}",
                f"{last}.{first}",
                f"{first}{last[0]}",
            }
        )
    # If middle name present
    if len(parts) > 2:
        middle = parts[1]
        out.add(f"{first}{middle}{last}")
        out.add(f"{first}.{middle}.{last}")
        out.add(f"{first[0]}{middle[0]}{last}")
    # Hint-suffixed variants
    hint_clean = (hint or "").strip().lower().split()[0:1]
    if hint_clean:
        h = hint_clean[0]
        out.update({f"{first}{last}{h}", f"{first}.{last}.{h}", f"{first}_{last}_{h}"})
    # Drop anything too short or with weird chars
    out = {x for x in out if 3 <= len(x) <= 30 and all(c.isalnum() or c in "._-" for c in x)}
    return sorted(out)


class UsernamePermutator(BaseModule):
    """A 'pseudo-module' that emits permutations as data. Not a real source check —
    its findings are consumed by the correlator to spawn downstream username runs."""

    @property
    def name(self) -> str:
        return "name_permutator"

    @property
    def category(self) -> str:
        return "name"

    @property
    def modes_allowed(self) -> set[str]:
        return {"prospect", "selfcheck", "pentest"}

    @property
    def host(self) -> str:
        return "local"

    @property
    def rate_limit_per_min(self) -> int:
        return 6000

    async def run(self, target: Target, client) -> Finding:  # noqa: ANN001
        import os

        hint = os.environ.get("OSINT_HINT", "")
        perms = permutations(target.value, hint=hint)
        return Finding(
            source=self.name,
            target_value=target.value,
            status=Status.FOUND if perms else Status.NOT_FOUND,
            confidence=Confidence.LOW,
            data={
                "permutations": perms,
                "count": len(perms),
                "hint_used": hint or None,
            },
        )
