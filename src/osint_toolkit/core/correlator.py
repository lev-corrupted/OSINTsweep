"""Cross-source correlator.

After a Report comes back, walks every Finding for identifiers that could be the input
to a downstream lookup. Returns a list of derived Targets.

Examples:
- Gravatar finding includes `preferred_username` → derive Target(USERNAME, value).
- Gravatar finding includes account shortnames (twitter, github) → derive Target(USERNAME, value).
- DNS MX finding for a custom domain → derive Target(DOMAIN, value) for future-domain modules.

Recursion is capped at depth=1 to avoid runaway expansion.
"""

from __future__ import annotations

from osint_toolkit.core.models import Finding, Report, Target, TargetKind


def derive_targets(report: Report) -> list[Target]:
    """Look at a report's findings, propose new Targets to feed back to a Dispatcher."""
    derived: list[Target] = []
    seen: set[tuple[TargetKind, str]] = {(report.target.kind, report.target.value)}

    if report.target.kind == TargetKind.EMAIL:
        local_part = report.target.value.split("@")[0]
        if local_part and len(local_part) >= 3:
            key = (TargetKind.USERNAME, local_part)
            if key not in seen:
                try:
                    derived.append(Target(kind=TargetKind.USERNAME, value=local_part))
                    seen.add(key)
                except Exception:  # noqa: BLE001
                    pass

    for f in report.findings:
        for kind, value in _candidates_from_finding(f):
            key = (kind, value)
            if key in seen:
                continue
            try:
                t = Target(kind=kind, value=value)
            except Exception:  # noqa: BLE001, S110, S112
                continue
            seen.add(key)
            derived.append(t)
    return derived


def _candidates_from_finding(f: Finding) -> list[tuple[TargetKind, str]]:
    out: list[tuple[TargetKind, str]] = []
    data = f.data or {}
    if f.source == "gravatar":
        if pu := data.get("preferred_username"):
            out.append((TargetKind.USERNAME, pu))
        for acct in data.get("accounts") or []:
            if isinstance(acct, str) and acct:
                out.append((TargetKind.USERNAME, acct))
    if f.source == "gravatar_profile":
        if pu := data.get("preferred_username"):
            out.append((TargetKind.USERNAME, pu))
    # Name → username permutations
    if f.source == "name_permutator":
        # Cap to top 6 to avoid 6×80=480 requests per name lookup
        for perm in (data.get("permutations") or [])[:6]:
            out.append((TargetKind.USERNAME, perm))
    return out
