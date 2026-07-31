"""Parser round-trip: WatchGuard XML -> JSON -> WatchGuardConfig model."""
import glob
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "sample_config.xml"


@pytest.fixture(scope="module")
def parsed_json(tmp_path_factory):
    """Run the JSON parser on the fixture XML and load its output."""
    workdir = tmp_path_factory.mktemp("parser")
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "watchparse-json-v5.py"), str(FIXTURE)],
        cwd=workdir, capture_output=True, text=True
    )
    assert result.returncode == 0, f"parser failed:\n{result.stdout}\n{result.stderr}"
    outputs = glob.glob(str(workdir / "watchguard_config_v5_*.json"))
    assert len(outputs) == 1, f"expected one output file, got {outputs}"
    with open(outputs[0]) as f:
        return json.load(f)


def test_addresses_parsed(parsed_json):
    hosts = {h["name"]: h for h in parsed_json["addresses"]["hosts"]}
    networks = {n["name"]: n for n in parsed_json["addresses"]["networks"]}
    assert hosts["WebServer"]["ip"] == "10.0.1.10"
    assert networks["LAN-Net"]["network"] == "10.0.0.0"
    assert networks["LAN-Net"]["mask"] == "255.255.0.0"


def test_service_dedup_creates_group(parsed_json):
    """PDQ has TCP+UDP definitions -> unique names plus a service group."""
    tcp = {s["name"]: s for s in parsed_json["services"]["tcp"]}
    udp = {s["name"]: s for s in parsed_json["services"]["udp"]}
    assert "PDQ_TCP_139" in tcp
    assert tcp["PDQ_TCP_139"]["original_name"] == "PDQ"
    assert "PDQ_UDP_137" in udp

    groups = {g["original_name"]: g for g in parsed_json["service_groups"]}
    assert "PDQ" in groups
    assert set(groups["PDQ"]["members"]) == {"PDQ_TCP_139", "PDQ_UDP_137"}


def test_single_service_keeps_name(parsed_json):
    tcp = {s["name"]: s for s in parsed_json["services"]["tcp"]}
    assert "HTTP-Custom" in tcp
    assert tcp["HTTP-Custom"]["port"] == "8080"


def test_icmp_service_separate(parsed_json):
    icmp = {s["name"]: s for s in parsed_json["services"]["icmp"]}
    assert "Ping" in icmp


def test_policies_parsed_with_aliases(parsed_json):
    policies = {p["name"]: p for p in parsed_json["policies"]}
    assert len(policies) == 4

    web = policies["Allow Web Traffic"]
    assert web["service"] == "HTTP-Custom"
    assert set(web["source_members"]) == {"WebServer", "LAN-Net"}
    assert web["destination_members"] == ["WebServer"]

    # Interface alias resolves to no members, but raw alias name is kept
    ping = policies["Ping To Firebox"]
    assert ping["destination_members"] == []
    assert ping["destination_aliases"] == ["Firebox"]


def test_model_round_trip(parsed_json):
    """Parsed JSON loads into the WatchGuardConfig model."""
    from models import WatchGuardConfig
    config = WatchGuardConfig.from_json(parsed_json)

    assert len(config.hosts) == 1
    assert len(config.networks) == 1
    assert len(config.policies) == 4
    assert len(config.service_groups) == 1

    ping = next(p for p in config.policies if p.name == "Ping To Firebox")
    assert ping.destination_aliases == ["Firebox"]
    assert ping.enabled is True

    # Service resolution: PDQ resolves to its group
    resolved = config.resolve_service("PDQ")
    assert resolved["type"] == "group"
