"""Plan file round-trip: save -> load -> identical plan."""
from dataclasses import asdict

import pytest

from models import (
    WatchGuardAddress, WatchGuardService, WatchGuardAddressGroup,
    WatchGuardServiceGroup, FMCObject,
)
from migration.planner import MigrationPlan
from migration import planfile


@pytest.fixture
def sample_plan():
    return MigrationPlan(
        address_mappings={
            "ExistingHost": FMCObject(id="abc123", name="ExistingHost", type="Host"),
        },
        service_mappings={
            "HTTPS": FMCObject(id="svc1", name="HTTPS", type="ProtocolPortObject",
                               protocol="TCP", port="443", is_builtin=True),
        },
        application_mappings={
            "Outlook": FMCObject(id="app1", name="Outlook", type="Application"),
        },
        objects_to_create=[
            {"type": "host",
             "wg_object": WatchGuardAddress(name="WebServer", ip="10.0.1.10")},
            {"type": "network",
             "wg_object": WatchGuardAddress(name="LAN-Net", network="10.0.0.0",
                                            mask="255.255.0.0")},
            {"type": "service",
             "wg_object": WatchGuardService(name="PDQ_TCP_139", protocol="TCP",
                                            port="139", original_name="PDQ")},
            {"type": "address_group",
             "wg_object": WatchGuardAddressGroup(name="Trusted-Hosts",
                                                 members=["WebServer", "LAN-Net"])},
        ],
        policies_to_create=[
            {"wg_policy": "Allow Web Traffic",
             "classification": "traffic",
             "fmc_rule": {"name": "Allow Web Traffic", "action": "ALLOW",
                          "enabled": True},
             "warnings": ["example warning"],
             "errors": []},
        ],
        statistics={"total_wg_objects": 4, "needs_creation": 4},
        service_groups_to_create=[
            WatchGuardServiceGroup(name="PDQ_svc_group", original_name="PDQ",
                                   members=["PDQ_TCP_139", "PDQ_UDP_137"]),
        ],
        skipped_policies=[
            {"name": "WatchGuard Web UI", "classification": "management-plane",
             "reason": "WatchGuard device management policy (by name)",
             "included": False},
        ],
    )


def _plan_fingerprint(plan):
    """Comparable representation of every field the executor consumes."""
    return {
        "address_mappings": {k: asdict(v) for k, v in plan.address_mappings.items()},
        "service_mappings": {k: asdict(v) for k, v in plan.service_mappings.items()},
        "application_mappings": {k: asdict(v) for k, v in plan.application_mappings.items()},
        "objects_to_create": [
            {"type": e["type"], "wg_object": asdict(e["wg_object"]),
             "wg_class": type(e["wg_object"]).__name__}
            for e in plan.objects_to_create
        ],
        "service_groups_to_create": [asdict(g) for g in plan.service_groups_to_create],
        "policies_to_create": plan.policies_to_create,
        "statistics": plan.statistics,
        "skipped_policies": plan.skipped_policies,
    }


def test_round_trip(sample_plan, tmp_path):
    plan_file = tmp_path / "plan.json"
    planfile.save_plan(sample_plan, str(plan_file),
                       metadata={"source_config": "test.json"})

    loaded = planfile.load_plan(str(plan_file))

    assert _plan_fingerprint(loaded) == _plan_fingerprint(sample_plan)
    # Derived properties survive because they're computed from policies_to_create
    assert loaded.warnings == sample_plan.warnings
    assert loaded.errors == sample_plan.errors


def test_dataclass_types_restored(sample_plan, tmp_path):
    plan_file = tmp_path / "plan.json"
    planfile.save_plan(sample_plan, str(plan_file))
    loaded = planfile.load_plan(str(plan_file))

    types = [type(e["wg_object"]).__name__ for e in loaded.objects_to_create]
    assert types == ["WatchGuardAddress", "WatchGuardAddress",
                     "WatchGuardService", "WatchGuardAddressGroup"]
    # Property logic works on restored objects
    assert loaded.objects_to_create[0]["wg_object"].object_type == "host"
    assert isinstance(loaded.service_groups_to_create[0], WatchGuardServiceGroup)


def test_rejects_old_format(tmp_path):
    """Files from the pre-v9 summary format are rejected with a clear error."""
    old = tmp_path / "old_plan.json"
    old.write_text('{"statistics": {}, "objects_to_create": 42}')
    with pytest.raises(ValueError, match="format_version"):
        planfile.load_plan(str(old))


def test_rejects_future_version(tmp_path, sample_plan):
    import json
    plan_file = tmp_path / "plan.json"
    planfile.save_plan(sample_plan, str(plan_file))
    data = json.loads(plan_file.read_text())
    data["format_version"] = 999
    plan_file.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="v999"):
        planfile.load_plan(str(plan_file))


def test_hand_edit_removes_policy(sample_plan, tmp_path):
    """The review-and-edit gate: deleting a policy from the file works."""
    import json
    plan_file = tmp_path / "plan.json"
    planfile.save_plan(sample_plan, str(plan_file))

    data = json.loads(plan_file.read_text())
    data["policies_to_create"] = []
    plan_file.write_text(json.dumps(data))

    loaded = planfile.load_plan(str(plan_file))
    assert loaded.policies_to_create == []
    # Objects unaffected
    assert len(loaded.objects_to_create) == 4
