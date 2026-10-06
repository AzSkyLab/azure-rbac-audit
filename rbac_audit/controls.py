"""Control tests and exception lists."""
from __future__ import annotations

from .pim import PERMANENT_ACTIVE
from .principals import DIRECT_USER_TYPES, ORPHANED
from .roles import STANDARD

PASS, FAIL, REVIEW = "PASS", "FAIL", "REVIEW"


def direct_user_result(principal_type: str, resolution: str = "resolved") -> str:
    """Control: no direct user assignments (active or eligible).

    A principal whose type could not be confirmed (orphaned, or Graph lookup failed) is never a PASS;
    one already known to be a User/Guest still fails.
    """
    if principal_type in DIRECT_USER_TYPES:
        return FAIL
    if principal_type == ORPHANED or resolution != "resolved":
        return REVIEW
    return PASS


def direct_user_exceptions(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["direct_user_result"] == FAIL]


def privileged_permanent_exceptions(rows: list[dict]) -> list[dict]:
    return [r for r in rows if r["privilege_tier"] != STANDARD and r["pim_label"] == PERMANENT_ACTIVE]


ALLOWLISTED_COLUMNS = ["exception_file", "assignment_id", "principal_id", "principal_type", "principal_name", "role_name",
                       "scope", "pim_label", "allowlist_reason"]


def apply_allowlist(rows: list[dict], entries, exception_file: str, used: set[int]) -> tuple[list[dict], list[dict]]:
    """Split exception rows into (kept, allowlisted). Allowlisted rows are not dropped: they are written to
    exceptions_allowlisted.csv with the configured justification. `used` collects indexes of entries that matched."""
    kept, accepted = [], []
    for r in rows:
        hit = next(((i, e) for i, e in enumerate(entries) if e.matches(r)), None)
        if hit is None:
            kept.append(r)
            continue
        used.add(hit[0])
        accepted.append({**{k: r.get(k, "") for k in ALLOWLISTED_COLUMNS}, "exception_file": exception_file,
                         "allowlist_reason": hit[1].reason})
    return kept, accepted
