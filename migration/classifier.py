"""
Policy Classifier - Tags WatchGuard policies by role before planning.

Classes:
  traffic           Normal user/network traffic policy - migrate to the ACP.
  management-plane  WatchGuard device management (Web UI, cert portal,
                    WatchGuard Cloud, ping-to-firebox, VPN termination on the
                    firebox itself). FTD handles management access through
                    platform settings, not the ACP - skipped by default.
  default-deny      WatchGuard's built-in catch-all deny/logging rules
                    (Unhandled Internal/External Packet). The FMC ACP default
                    action covers this - skipped by default.

Classification is intentionally data-driven so new patterns can be added
without touching logic.
"""

from typing import List
from models import WatchGuardPolicy


# WatchGuard built-in cleanup rules; equivalent to the ACP default action.
DEFAULT_DENY_NAMES = {
    "unhandled internal packet",
    "unhandled external packet",
}

# Exact policy names that are device management-plane.
MANAGEMENT_NAMES = {
    "ping to firebox",
    "any from firebox",
}

# Name prefixes that indicate WatchGuard device/management policies.
MANAGEMENT_NAME_PREFIXES = (
    "watchguard ",
)

# Alias names that refer to the WatchGuard device itself. A policy whose
# source or destination is the firebox is management-plane traffic.
FIREBOX_ALIASES = {
    "firebox",
}

# Service name prefixes for WatchGuard management services.
MANAGEMENT_SERVICE_PREFIXES = (
    "wg-",
)

CLASS_TRAFFIC = "traffic"
CLASS_MANAGEMENT = "management-plane"
CLASS_DEFAULT_DENY = "default-deny"

SKIPPED_CLASSES = (CLASS_MANAGEMENT, CLASS_DEFAULT_DENY)


def classify_policy(policy: WatchGuardPolicy) -> str:
    """Classify a single WatchGuard policy.

    Returns one of: CLASS_TRAFFIC, CLASS_MANAGEMENT, CLASS_DEFAULT_DENY.
    """
    name_lower = (policy.name or "").strip().lower()

    if name_lower in DEFAULT_DENY_NAMES:
        return CLASS_DEFAULT_DENY

    if name_lower in MANAGEMENT_NAMES:
        return CLASS_MANAGEMENT

    if name_lower.startswith(MANAGEMENT_NAME_PREFIXES):
        return CLASS_MANAGEMENT

    # Policies to or from the firebox itself are management-plane. Check the
    # raw alias names as well as resolved members: interface aliases like
    # 'Firebox' resolve to no address members, so they only appear in the
    # alias lists.
    members = [m.strip().lower() for m in
               (policy.source_members or []) + (policy.destination_members or []) +
               (getattr(policy, 'source_aliases', None) or []) +
               (getattr(policy, 'destination_aliases', None) or [])]
    if any(m in FIREBOX_ALIASES for m in members):
        return CLASS_MANAGEMENT

    # Policies whose service is a WatchGuard management service.
    service_lower = (policy.service or "").strip().lower()
    if service_lower.startswith(MANAGEMENT_SERVICE_PREFIXES):
        return CLASS_MANAGEMENT

    return CLASS_TRAFFIC


def classification_reason(policy: WatchGuardPolicy, cls: str) -> str:
    """Human-readable reason for a classification (for the plan report)."""
    if cls == CLASS_DEFAULT_DENY:
        return "WatchGuard built-in catch-all; covered by the ACP default action"
    if cls == CLASS_MANAGEMENT:
        name_lower = (policy.name or "").strip().lower()
        if name_lower in MANAGEMENT_NAMES or name_lower.startswith(MANAGEMENT_NAME_PREFIXES):
            return "WatchGuard device management policy (by name)"
        members = [m.strip().lower() for m in
                   (policy.source_members or []) + (policy.destination_members or []) +
                   (getattr(policy, 'source_aliases', None) or []) +
                   (getattr(policy, 'destination_aliases', None) or [])]
        if any(m in FIREBOX_ALIASES for m in members):
            return "Source or destination is the Firebox itself"
        return "Uses a WatchGuard management service (WG-*)"
    return "Normal traffic policy"


def split_policies(policies: List[WatchGuardPolicy],
                   include_management: bool = False):
    """Split policies into (to_migrate, skipped_report).

    skipped_report is a list of dicts: {name, classification, reason}.
    When include_management is True, everything migrates and the report
    lists non-traffic policies as included (informational).
    """
    to_migrate = []
    skipped = []

    for policy in policies:
        cls = classify_policy(policy)
        if cls == CLASS_TRAFFIC or include_management:
            to_migrate.append(policy)
            if cls != CLASS_TRAFFIC:
                skipped.append({
                    "name": policy.name,
                    "classification": cls,
                    "reason": classification_reason(policy, cls),
                    "included": True,
                })
        else:
            skipped.append({
                "name": policy.name,
                "classification": cls,
                "reason": classification_reason(policy, cls),
                "included": False,
            })

    return to_migrate, skipped
