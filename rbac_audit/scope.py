"""Scope-string helpers."""
from __future__ import annotations

import re

_MG = re.compile(r"^/providers/microsoft\.management/managementgroups/[^/]+$", re.I)
_SUB = re.compile(r"^/subscriptions/([^/]+)$", re.I)
_RG = re.compile(r"^/subscriptions/([^/]+)/resourcegroups/([^/]+)$", re.I)
_SUB_PREFIX = re.compile(r"^/subscriptions/([^/]+)", re.I)
_RG_PREFIX = re.compile(r"^/subscriptions/[^/]+/resourcegroups/([^/]+)", re.I)

BROAD_LEVELS = frozenset({"root", "management_group", "subscription"})


def scope_level(scope: str) -> str:
    s = (scope or "").rstrip("/")
    if s == "":
        return "root"
    if _MG.match(s):
        return "management_group"
    if _SUB.match(s):
        return "subscription"
    if _RG.match(s):
        return "resource_group"
    return "resource"


def subscription_id(scope: str) -> str:
    m = _SUB_PREFIX.match(scope or "")
    return m.group(1).lower() if m else ""


def resource_group(scope: str) -> str:
    m = _RG_PREFIX.match(scope or "")
    return m.group(1) if m else ""


def guid_of(resource_id: str | None) -> str:
    """Last path segment, lowercased: normalises role definition / assignment ids."""
    return (resource_id or "").rstrip("/").rsplit("/", 1)[-1].lower()
