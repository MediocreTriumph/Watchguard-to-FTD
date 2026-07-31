"""Policy classification tests - names taken from a real migration audit."""
import pytest

from models import WatchGuardPolicy
from migration.classifier import (
    classify_policy, split_policies,
    CLASS_TRAFFIC, CLASS_MANAGEMENT, CLASS_DEFAULT_DENY,
)


def make_policy(name, src=None, dst=None, service="Any",
                src_aliases=None, dst_aliases=None):
    return WatchGuardPolicy(
        name=name,
        source_members=src or [],
        destination_members=dst or [],
        service=service,
        action="Allow",
        enabled=True,
        source_aliases=src_aliases or [],
        destination_aliases=dst_aliases or [],
    )


@pytest.mark.parametrize("name", [
    "WatchGuard Certificate Portal",
    "WatchGuard SSLVPN",
    "WatchGuard Threat Detection and Re",
    "WatchGuard Cloud",
    "WatchGuard Web UI",
    "WatchGuard SSL Mobile VPN",
    "Ping To Firebox",
    "Any From Firebox",
])
def test_management_by_name(name):
    assert classify_policy(make_policy(name)) == CLASS_MANAGEMENT


@pytest.mark.parametrize("name", [
    "Unhandled Internal Packet",
    "Unhandled External Packet",
])
def test_default_deny(name):
    assert classify_policy(make_policy(name)) == CLASS_DEFAULT_DENY


@pytest.mark.parametrize("name", [
    "Guest",
    "Outgoing",
    "Guest.web",
    "Outgoing.FTP",
    "BOVPN-Allow-Any.in",
    "Allow SSLVPN-Users",
    "Allow DNS-Forwarding",
    "Meraki Switch Interface 6 Traffic",
    "Allow Web Traffic",
])
def test_traffic(name):
    assert classify_policy(make_policy(name)) == CLASS_TRAFFIC


def test_firebox_destination_via_alias():
    """Interface alias 'Firebox' resolves to no members - the raw alias
    name must still trigger management-plane classification."""
    p = make_policy("Allow Admin Access", dst_aliases=["Firebox"])
    assert classify_policy(p) == CLASS_MANAGEMENT


def test_firebox_in_resolved_members():
    p = make_policy("Custom Rule", dst=["Firebox"])
    assert classify_policy(p) == CLASS_MANAGEMENT


def test_wg_service_prefix():
    p = make_policy("Custom Mgmt Rule", service="WG-Cert-Portal.1")
    assert classify_policy(p) == CLASS_MANAGEMENT


def test_split_policies_default_skips():
    policies = [
        make_policy("Allow Web Traffic"),
        make_policy("WatchGuard Web UI"),
        make_policy("Unhandled Internal Packet"),
    ]
    to_migrate, skipped = split_policies(policies)
    assert [p.name for p in to_migrate] == ["Allow Web Traffic"]
    assert len(skipped) == 2
    assert all(not s["included"] for s in skipped)
    assert {s["classification"] for s in skipped} == {CLASS_MANAGEMENT, CLASS_DEFAULT_DENY}
    assert all(s["reason"] for s in skipped)


def test_split_policies_include_management():
    policies = [
        make_policy("Allow Web Traffic"),
        make_policy("WatchGuard Web UI"),
        make_policy("Unhandled Internal Packet"),
    ]
    to_migrate, report = split_policies(policies, include_management=True)
    assert len(to_migrate) == 3
    # Non-traffic policies still reported, marked as included
    assert len(report) == 2
    assert all(s["included"] for s in report)
