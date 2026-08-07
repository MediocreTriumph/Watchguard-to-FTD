"""Tests for explicit alias->zone mapping (v10)."""
import json

import pytest

from models import WatchGuardConfig, FMCObject
from fmc.zone_mapping import (
    AliasZoneMapper, ZoneNameResolver,
    collect_zone_template_aliases, write_zone_template,
)
from migration.planner import MigrationPlanner, MigrationPlan
from migration.executor import MigrationExecutor


@pytest.fixture
def mappings_file(tmp_path):
    f = tmp_path / "zone_mappings.json"
    f.write_text(json.dumps({
        "mappings": {
            "Any-Trusted": "INSIDE",
            "Any-External": "OUTSIDE",
            "SSLVPN-Users": "RAVPN",
            "Any-Optional": "",
        }
    }))
    return str(f)


# ---------------------------------------------------------------- mapper

def test_zones_for_aliases(mappings_file):
    m = AliasZoneMapper(mappings_file)
    zones, unmapped = m.zones_for_aliases(["Any-Trusted", "SSLVPN-Users"])
    assert zones == ["INSIDE", "RAVPN"]
    assert unmapped == []


def test_alias_lookup_case_insensitive(mappings_file):
    m = AliasZoneMapper(mappings_file)
    zones, _ = m.zones_for_aliases(["any-trusted"])
    assert zones == ["INSIDE"]


def test_empty_mapping_means_no_zone(mappings_file):
    m = AliasZoneMapper(mappings_file)
    zones, unmapped = m.zones_for_aliases(["Any-Optional"])
    assert zones == []
    assert unmapped == []  # explicitly zoneless, not unmapped


def test_any_is_implicitly_zoneless(mappings_file):
    m = AliasZoneMapper(mappings_file)
    zones, unmapped = m.zones_for_aliases(["Any"])
    assert zones == []
    assert unmapped == []


def test_unmapped_alias_reported(mappings_file):
    m = AliasZoneMapper(mappings_file)
    zones, unmapped = m.zones_for_aliases(["Mystery-Alias"])
    assert zones == []
    assert unmapped == ["Mystery-Alias"]
    assert m.get_report()["unmapped_aliases_seen"] == ["Mystery-Alias"]


def test_duplicate_zones_deduplicated(mappings_file):
    m = AliasZoneMapper(mappings_file)
    zones, _ = m.zones_for_aliases(["Any-Trusted", "any-trusted"])
    assert zones == ["INSIDE"]


# ---------------------------------------------------------------- template

WG_DATA = {
    "interface_aliases": [
        {"name": "Any-Trusted"}, {"name": "Any-External"}, {"name": "Firebox"},
    ],
    "address_groups": [{"name": "Trusted-Hosts"}],
    "policies": [
        {"source_aliases": ["Any-Trusted", "SSLVPN-Users"],
         "destination_aliases": ["Trusted-Hosts", "Any-External"]},
    ],
}


def test_collect_template_aliases():
    aliases = collect_zone_template_aliases(WG_DATA)
    assert "Any-Trusted" in aliases
    assert "SSLVPN-Users" in aliases        # policy alias, not an address group
    assert "Trusted-Hosts" not in aliases   # address group: scopes by address


def test_write_template(tmp_path):
    out = tmp_path / "template.json"
    count = write_zone_template(WG_DATA, str(out))
    data = json.loads(out.read_text())
    assert count == len(data["mappings"])
    assert data["mappings"]["Any-Trusted"] == "INSIDE"   # suggested default
    assert data["mappings"]["SSLVPN-Users"] == ""        # user decision


# ---------------------------------------------------------------- planner

def make_planner(mapper):
    wg = WatchGuardConfig.from_json({
        "policies": [
            {"name": "Outgoing", "source_members": [], "destination_members": [],
             "service": "Any", "action": "Allow", "enabled": "true",
             "source_aliases": ["Any-Trusted"],
             "destination_aliases": ["Any-External"]},
            {"name": "NoZones", "source_members": [], "destination_members": [],
             "service": "Any", "action": "Allow", "enabled": "true",
             "source_aliases": ["Any"], "destination_aliases": ["Any"]},
        ]
    })
    return MigrationPlanner(wg, fmc_discovery=None, service_mapper=object(),
                            app_mapper=object(), alias_zone_mapper=mapper)


def test_planner_stamps_zone_names(mappings_file):
    plan = make_planner(AliasZoneMapper(mappings_file)).build_plan()
    by_name = {p['wg_policy']: p for p in plan.policies_to_create}
    assert by_name["Outgoing"]["source_zones"] == ["INSIDE"]
    assert by_name["Outgoing"]["destination_zones"] == ["OUTSIDE"]
    assert by_name["NoZones"]["source_zones"] == []
    assert plan.statistics["policies_with_zones"] == 1


def test_planner_without_mapper_has_empty_zones():
    plan = make_planner(None).build_plan()
    for p in plan.policies_to_create:
        assert p["source_zones"] == []
        assert p["destination_zones"] == []


def test_planner_expands_nested_aliases(tmp_path):
    """Real WatchGuard structure: policies reference per-policy aliases
    ('Outgoing.1.from') that nest interface aliases as alias_references.
    Zone mapping must see through the nesting - regression for the bug
    where every policy planned with zero zones."""
    f = tmp_path / "zone_mappings.json"
    f.write_text(json.dumps({"mappings": {
        "Any-Internal": "INSIDE",
        "Any-External": "OUTSIDE",
        "Any-Guest": "GUEST",
    }}))

    wg = WatchGuardConfig.from_json({
        "address_groups": [
            {"name": "Outgoing.1.from", "alias_references": ["Any-Internal"]},
            {"name": "Outgoing.1.to", "alias_references": ["Any-External"]},
            {"name": "Guest.1.from", "alias_references": ["Any-Guest"]},
        ],
        "interface_aliases": [
            {"name": "Any-Internal", "member_interfaces": ["eth1"]},
            {"name": "Any-External", "member_interfaces": ["eth0"]},
            {"name": "Any-Guest", "member_interfaces": ["eth2"]},
        ],
        "policies": [
            {"name": "Outgoing", "source_members": [], "destination_members": [],
             "service": "Any", "action": "Allow", "enabled": "true",
             "source_aliases": ["Outgoing.1.from"],
             "destination_aliases": ["Outgoing.1.to"]},
            {"name": "Guest", "source_members": [], "destination_members": [],
             "service": "Any", "action": "Allow", "enabled": "true",
             "source_aliases": ["Guest.1.from"],
             "destination_aliases": ["Any"]},
        ],
    })
    planner = MigrationPlanner(wg, fmc_discovery=None, service_mapper=object(),
                               app_mapper=object(),
                               alias_zone_mapper=AliasZoneMapper(str(f)))
    plan = planner.build_plan()
    by_name = {p['wg_policy']: p for p in plan.policies_to_create}
    assert by_name["Outgoing"]["source_zones"] == ["INSIDE"]
    assert by_name["Outgoing"]["destination_zones"] == ["OUTSIDE"]
    assert by_name["Guest"]["source_zones"] == ["GUEST"]
    assert by_name["Guest"]["destination_zones"] == []
    assert plan.statistics["policies_with_zones"] == 2


def test_alias_expansion_handles_cycles(tmp_path):
    f = tmp_path / "zone_mappings.json"
    f.write_text(json.dumps({"mappings": {"Any-Internal": "INSIDE"}}))
    wg = WatchGuardConfig.from_json({
        "address_groups": [
            {"name": "A", "alias_references": ["B"]},
            {"name": "B", "alias_references": ["A", "Any-Internal"]},
        ],
        "interface_aliases": [
            {"name": "Any-Internal", "member_interfaces": ["eth1"]},
        ],
        "policies": [
            {"name": "Loopy", "source_members": [], "destination_members": [],
             "service": "Any", "action": "Allow", "enabled": "true",
             "source_aliases": ["A"], "destination_aliases": []},
        ],
    })
    planner = MigrationPlanner(wg, fmc_discovery=None, service_mapper=object(),
                               app_mapper=object(),
                               alias_zone_mapper=AliasZoneMapper(str(f)))
    plan = planner.build_plan()
    assert plan.policies_to_create[0]["source_zones"] == ["INSIDE"]


# ---------------------------------------------------------------- executor

def make_executor():
    plan = MigrationPlan(
        address_mappings={}, service_mappings={}, application_mappings={},
        objects_to_create=[], policies_to_create=[], statistics={},
    )
    resolver = ZoneNameResolver(fmc_client=None)
    resolver.zones_by_name = {
        "inside": {"name": "INSIDE", "id": "z1", "type": "SecurityZone"},
        "outside": {"name": "OUTSIDE", "id": "z2", "type": "SecurityZone"},
    }
    return MigrationExecutor(fmc_client=None, plan=plan, zone_resolver=resolver)


def test_executor_applies_explicit_zones():
    ex = make_executor()
    rule = {"name": "Outgoing", "action": "ALLOW"}
    policy_data = {"source_zones": ["INSIDE"], "destination_zones": ["OUTSIDE"]}
    resolved, warnings = ex._resolve_rule_objects(rule, policy_data)
    assert resolved["sourceZones"]["objects"][0]["id"] == "z1"
    assert resolved["destinationZones"]["objects"][0]["id"] == "z2"
    assert warnings == []
    assert ex.rules_with_zones == 1


def test_executor_warns_on_missing_zone():
    ex = make_executor()
    rule = {"name": "Outgoing", "action": "ALLOW"}
    policy_data = {"source_zones": ["GUEST"], "destination_zones": []}
    resolved, warnings = ex._resolve_rule_objects(rule, policy_data)
    assert "sourceZones" not in resolved
    assert any(w["type"] == "zone_mapping" and "GUEST" in w["message"]
               for w in warnings)


def test_executor_no_zones_no_change():
    ex = make_executor()
    rule = {"name": "Plain", "action": "ALLOW"}
    resolved, warnings = ex._resolve_rule_objects(rule, {})
    assert "sourceZones" not in resolved
    assert "destinationZones" not in resolved
    assert warnings == []
