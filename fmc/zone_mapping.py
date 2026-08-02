"""
Explicit alias-to-zone mapping (v10).

WatchGuard policies are scoped by interface aliases (Any-Trusted,
Any-External, custom VPN aliases). Those aliases resolve to no address
objects, so migrated rules silently lost their scoping. This module maps
alias names to FMC security zone names explicitly, via a user-edited
JSON file:

    {
      "_comment": "WatchGuard alias -> FMC security zone name",
      "mappings": {
        "Any-Trusted": "INSIDE",
        "Any-External": "OUTSIDE",
        "SSLVPN-Users": "RAVPN",
        "Any": ""
      }
    }

An empty string means "no zone" (leave that side unconstrained).

Two classes, deliberately separate:
  AliasZoneMapper   planning time - alias names -> zone NAMES (no FMC needed)
  ZoneNameResolver  execution time - zone names -> FMC SecurityZone refs
"""

import json
from typing import Dict, List, Optional, Tuple


class AliasZoneMapper:
    """Maps WatchGuard alias names to FMC zone names from a mappings file."""

    def __init__(self, mappings_file: str):
        self.mappings_file = mappings_file
        self.mappings: Dict[str, str] = {}
        self.unmapped_seen: set = set()

        with open(mappings_file, 'r') as f:
            data = json.load(f)
        raw = data.get('mappings', {})
        if not isinstance(raw, dict):
            raise ValueError(f"{mappings_file}: 'mappings' must be an object")
        # Case-insensitive alias lookup; zone names kept verbatim
        self.mappings = {k.strip().lower(): (v or "").strip()
                         for k, v in raw.items()}

    def zones_for_aliases(self, aliases: List[str]) -> Tuple[List[str], List[str]]:
        """Map a policy's alias list to zone names.

        Returns (zone_names, unmapped_aliases). Aliases mapped to "" are
        intentionally zoneless and are neither returned nor unmapped.
        'Any' is implicitly zoneless unless explicitly mapped.
        """
        zones: List[str] = []
        unmapped: List[str] = []
        for alias in aliases or []:
            key = alias.strip().lower()
            if key in self.mappings:
                zone = self.mappings[key]
                if zone and zone not in zones:
                    zones.append(zone)
            elif key == 'any':
                continue
            else:
                unmapped.append(alias)
                self.unmapped_seen.add(alias)
        return zones, unmapped

    def get_report(self) -> Dict:
        return {
            'mappings_file': self.mappings_file,
            'mappings_loaded': len(self.mappings),
            'unmapped_aliases_seen': sorted(self.unmapped_seen),
        }


class ZoneNameResolver:
    """Resolves zone names to FMC SecurityZone object references."""

    def __init__(self, fmc_client):
        self.fmc = fmc_client
        self.zones_by_name: Dict[str, Dict] = {}
        self.missing_zones: set = set()

    def discover(self) -> int:
        """Fetch security zones from FMC. Returns count found."""
        endpoint = (f"{self.fmc.base_url}/domain/{self.fmc.domain_uuid}"
                    f"/object/securityzones")
        for item in self.fmc.get_paginated(endpoint):
            ref = {'name': item['name'], 'id': item['id'],
                   'type': 'SecurityZone'}
            self.zones_by_name[item['name'].lower()] = ref
        return len(self.zones_by_name)

    def resolve(self, zone_name: str) -> Optional[Dict]:
        ref = self.zones_by_name.get(zone_name.strip().lower())
        if ref is None:
            self.missing_zones.add(zone_name)
        return ref

    def resolve_all(self, zone_names: List[str]) -> List[Dict]:
        refs = []
        for name in zone_names or []:
            ref = self.resolve(name)
            if ref:
                refs.append(ref)
        return refs


def collect_zone_template_aliases(wg_data: Dict) -> List[str]:
    """Collect alias names that likely need zone mappings, from parsed
    WatchGuard JSON: interface aliases plus any policy from/to alias that
    isn't an address group (address groups scope by address, not zone).
    """
    address_groups = {g['name'] for g in wg_data.get('address_groups', [])}
    names = []

    for alias in wg_data.get('interface_aliases', []):
        if alias.get('name') and alias['name'] not in names:
            names.append(alias['name'])

    for policy in wg_data.get('policies', []):
        for alias in (policy.get('source_aliases', []) +
                      policy.get('destination_aliases', [])):
            if alias and alias not in address_groups and alias not in names:
                names.append(alias)

    return names


def write_zone_template(wg_data: Dict, filename: str) -> int:
    """Write a zone mappings template file. Returns alias count."""
    aliases = collect_zone_template_aliases(wg_data)
    template = {
        "_comment": ("WatchGuard alias -> FMC security zone name. "
                     "Empty string = no zone (leave unconstrained). "
                     "Zones must already exist in FMC at execution time."),
        "mappings": {alias: "" for alias in aliases},
    }
    # Sensible starting suggestions for WatchGuard built-ins
    for alias, suggestion in [("Any-Trusted", "INSIDE"),
                              ("Any-External", "OUTSIDE"),
                              ("Any-Optional", ""),
                              ("Any", "")]:
        if alias in template["mappings"]:
            template["mappings"][alias] = suggestion
    with open(filename, 'w') as f:
        json.dump(template, f, indent=2)
    return len(aliases)
