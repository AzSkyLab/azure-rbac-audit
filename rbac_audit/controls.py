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
