"""Regression tests for rule object resolution.

Bug: _is_interface_reference matched the bare substring 'vpn', so WatchGuard's
auto-generated per-policy address objects (e.g.
'Allow Servers to SSL VPN.1.from.1.pcy') were silently dropped from rules,
producing any/any rules in FMC.
"""
import pytest

from models import FMCObject
from migration.planner import MigrationPlan
from migration.executor import MigrationExecutor
from fmc.zones import ZoneMapper


def make_executor(known_objects=None):
    """Executor with no FMC connection and a minimal plan."""
    plan = MigrationPlan(
        address_mappings={}, service_mappings={}, application_mappings={},
        objects_to_create=[], policies_to_create=[], statistics={},
    )
    ex = MigrationExecutor(fmc_client=None, plan=plan)
    for name, obj in (known_objects or {}).items():
        ex.all_objects[name] = obj
    return ex


SSLVPN_OBJECTS = {
    "Allow Servers to SSL VPN.1.from.1.pcy": FMCObject(
        id="h1", name="Allow_Servers_to_SSL_VPN.1.from.1.pcy", type="Host"),
    "Allow Servers to SSL VPN.1.from.2.pcy": FMCObject(
        id="h2", name="Allow_Servers_to_SSL_VPN.1.from.2.pcy", type="Host"),
    "Allow Servers to SSL VPN.1.to.1.pcy": FMCObject(
        id="n1", name="Allow_Servers_to_SSL_VPN.1.to.1.pcy", type="Network"),
}


def test_vpn_named_objects_not_interface_refs():
    ex = make_executor()
    assert ex._is_interface_reference("Allow Servers to SSL VPN.1.from.1.pcy") is False
    assert ex._is_interface_reference("Tunnel-Switch-Mgmt") is False
    assert ex._is_interface_reference("VPN-Concentrator-Host") is False


def test_real_interface_refs_still_detected():
    ex = make_executor()
    for name in ["Any", "Any-Trusted", "Any-External", "Any-BOVPN", "Firebox"]:
        assert ex._is_interface_reference(name) is True, name
    assert ex._is_interface_reference("BOVPN-Peer-1") is True
    assert ex._is_interface_reference("muvpn-users") is True


def test_zone_mapper_heuristic_matches():
    zm = ZoneMapper(fmc_client=None)
    assert zm.is_interface_reference("Allow Servers to SSL VPN.1.from.1.pcy") is False
    assert zm.is_interface_reference("Any-BOVPN") is True
    assert zm.is_interface_reference("Firebox") is True


def test_resolution_keeps_vpn_named_objects():
    """The exact rule that lost its sources and destination in FMC."""
    ex = make_executor(SSLVPN_OBJECTS)
    rule = {
        "name": "Allow Servers to SSL VPN",
        "action": "ALLOW",
        "sourceNetworks": {"objects": [
            {"type": "Host", "name": "Allow Servers to SSL VPN.1.from.1.pcy"},
            {"type": "Host", "name": "Allow Servers to SSL VPN.1.from.2.pcy"},
        ]},
        "destinationNetworks": {"objects": [
            {"type": "Network", "name": "Allow Servers to SSL VPN.1.to.1.pcy"},
        ]},
    }
    resolved, warnings = ex._resolve_rule_objects(rule, {})

    src = resolved.get("sourceNetworks", {}).get("objects", [])
    dst = resolved.get("destinationNetworks", {}).get("objects", [])
    assert [o["id"] for o in src] == ["h1", "h2"]
    assert [o["id"] for o in dst] == ["n1"]
    assert warnings == []


def test_resolution_skips_unresolvable_interface_refs_silently():
    ex = make_executor(SSLVPN_OBJECTS)
    rule = {
        "name": "Mixed Rule",
        "action": "ALLOW",
        "sourceNetworks": {"objects": [
            {"type": "Host", "name": "Any-Trusted"},   # interface ref, no object
            {"type": "Host", "name": "Allow Servers to SSL VPN.1.from.1.pcy"},
        ]},
    }
    resolved, warnings = ex._resolve_rule_objects(rule, {})
    src = resolved.get("sourceNetworks", {}).get("objects", [])
    assert [o["id"] for o in src] == ["h1"]
    assert warnings == []  # interface ref skipped without warning


def test_resolution_warns_on_genuinely_missing_objects():
    ex = make_executor()
    rule = {
        "name": "Broken Rule",
        "action": "ALLOW",
        "sourceNetworks": {"objects": [
            {"type": "Host", "name": "No-Such-Object"},
        ]},
    }
    resolved, warnings = ex._resolve_rule_objects(rule, {})
    assert "sourceNetworks" not in resolved  # nothing resolved
    assert len(warnings) == 1
    assert warnings[0]["object"] == "No-Such-Object"
    assert warnings[0]["type"] == "unresolved"
