"""
FMC Security Zone Discovery and Network-Based Zone Inference.

v6.3: Zone inference based on source/destination network addresses.
      Examines the actual IP addresses in WatchGuard objects to determine zones:
      - RFC1918/private addresses → INSIDE zone
      - Public addresses → OUTSIDE zone
"""

import ipaddress
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from models import FMCObject


@dataclass
class ZoneMappingReport:
    """Zone mapping report for migration_report.json."""
    fmc_zones_found: List[str] = field(default_factory=list)
    fmc_zone_ids: Dict[str, str] = field(default_factory=dict)
    rules_with_zones: int = 0
    rules_without_zones: int = 0
    zone_inference_details: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fmc_zones_found": self.fmc_zones_found,
            "fmc_zone_ids": self.fmc_zone_ids,
            "rules_with_zones": self.rules_with_zones,
            "rules_without_zones": self.rules_without_zones,
            "zone_inference_sample": self.zone_inference_details[:20]
        }


class NetworkClassifier:
    """Classifies IP addresses/networks as internal (INSIDE) or external (OUTSIDE)."""
    
    RFC1918_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    
    PRIVATE_RANGES = [
        ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
        ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ]
    
    @classmethod
    def is_private_address(cls, value: str) -> Optional[bool]:
        """
        Check if an address value is private/internal.
        
        Args:
            value: IP address, network (CIDR), or range (start-end)
            
        Returns:
            True if private, False if public, None if can't determine
        """
        if not value or value in ["0.0.0.0", "", "any"]:
            return None
        
        # Handle range format "start-end"
        if '-' in value and '/' not in value:
            parts = value.split('-')
            if len(parts) == 2:
                start_result = cls._check_ip(parts[0].strip())
                end_result = cls._check_ip(parts[1].strip())
                if start_result == end_result:
                    return start_result
                return None
        
        # Handle CIDR format
        if '/' in value:
            return cls._check_network(value)
        
        # Single IP
        return cls._check_ip(value)
    
    @classmethod
    def _check_ip(cls, ip_str: str) -> Optional[bool]:
        """Check single IP address."""
        try:
            addr = ipaddress.ip_address(ip_str)
            
            if addr.is_loopback or addr.is_unspecified:
                return None
            
            for network in cls.RFC1918_RANGES:
                if addr in network:
                    return True
            
            for network in cls.PRIVATE_RANGES:
                if addr in network:
                    return True
            
            if addr.is_link_local or addr.is_private:
                return True
            
            if addr.is_global:
                return False
            
            return None
        except ValueError:
            return None
    
    @classmethod
    def _check_network(cls, network_str: str) -> Optional[bool]:
        """Check network in CIDR notation."""
        try:
            network = ipaddress.ip_network(network_str, strict=False)
            network_addr = network.network_address
            
            for priv_network in cls.RFC1918_RANGES:
                if network_addr in priv_network:
                    return True
            
            for priv_network in cls.PRIVATE_RANGES:
                if network_addr in priv_network:
                    return True
            
            if network_addr.is_global:
                return False
            
            return None
        except ValueError:
            return None


class ZoneMapper:
    """
    Maps zones for FMC rules based on network address classification.
    
    Examines IP addresses in source/destination networks to determine zones:
    - Private/RFC1918 addresses → INSIDE zone
    - Public addresses → OUTSIDE zone
    """
    
    def __init__(self, fmc_client, inside_zone: str = "INSIDE",
                 outside_zone: str = "OUTSIDE"):
        self.fmc = fmc_client
        self.inside_zone_name = inside_zone
        self.outside_zone_name = outside_zone
        self.expected_zones = [inside_zone, outside_zone]
        self.fmc_zones: Dict[str, FMCObject] = {}
        self.report = ZoneMappingReport()
        
        self._inside_zone_ref: Optional[Dict] = None
        self._outside_zone_ref: Optional[Dict] = None
        
        # Cache for WatchGuard object values (name -> IP value)
        self._wg_object_values: Dict[str, str] = {}
    
    def discover_fmc_zones(self) -> bool:
        """Discover existing security zones in FMC."""
        print("\n  Discovering FMC Security Zones...")
        
        endpoint = f"{self.fmc.base_url}/domain/{self.fmc.domain_uuid}/object/securityzones"
        items = self.fmc.get_paginated(endpoint)
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="SecurityZone"
            )
            self.fmc_zones[item['name']] = obj
            self.fmc_zones[item['name'].upper()] = obj
            self.report.fmc_zone_ids[item['name']] = item['id']
        
        unique_zones = set(obj.name for obj in self.fmc_zones.values())
        self.report.fmc_zones_found = list(unique_zones)
        
        print(f"  Found {len(unique_zones)} security zones: {', '.join(unique_zones)}")
        
        # Cache zone references
        missing = []
        for expected in self.expected_zones:
            zone_obj = self.fmc_zones.get(expected) or self.fmc_zones.get(expected.upper())
            if not zone_obj:
                missing.append(expected)
            else:
                zone_ref = {
                    "name": zone_obj.name,
                    "id": zone_obj.id,
                    "type": "SecurityZone"
                }
                if expected == self.inside_zone_name:
                    self._inside_zone_ref = zone_ref
                elif expected == self.outside_zone_name:
                    self._outside_zone_ref = zone_ref

        if missing:
            print(f"  ⚠ Missing expected zones: {', '.join(missing)}")
            return False

        print(f"  ✓ Inside zone '{self.inside_zone_name}': {self._inside_zone_ref['id']}")
        print(f"  ✓ Outside zone '{self.outside_zone_name}': {self._outside_zone_ref['id']}")
        return True
    
    def load_wg_object_values(self, wg_config):
        """
        Load IP values from WatchGuard config objects.
        
        Args:
            wg_config: WatchGuardConfig instance
        """
        print("  Loading WatchGuard object values for zone inference...")
        
        # Hosts: name -> IP
        for host in wg_config.hosts:
            if host.ip:
                self._wg_object_values[host.name] = host.ip
        
        # Networks: name -> network/mask (CIDR format)
        for network in wg_config.networks:
            if network.network and network.mask:
                # Convert to CIDR if needed
                mask = network.mask
                if '.' in mask:
                    # Convert dotted mask to CIDR prefix length
                    try:
                        prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
                        self._wg_object_values[network.name] = f"{network.network}/{prefix}"
                    except:
                        self._wg_object_values[network.name] = f"{network.network}/{mask}"
                else:
                    self._wg_object_values[network.name] = f"{network.network}/{mask}"
        
        # Ranges: name -> start-end
        for range_obj in wg_config.ranges:
            if range_obj.start and range_obj.end:
                self._wg_object_values[range_obj.name] = f"{range_obj.start}-{range_obj.end}"
        
        print(f"  ✓ Loaded {len(self._wg_object_values)} object values")
    
    def infer_zones_from_networks(
        self, 
        source_objects: List[Dict], 
        dest_objects: List[Dict],
        fmc_discovery,
        rule_name: str = ""
    ) -> Tuple[Optional[Dict], Optional[Dict], List[str]]:
        """
        Infer source and destination zones from network addresses.
        
        Args:
            source_objects: Resolved source network objects
            dest_objects: Resolved destination network objects
            fmc_discovery: FMCObjects (not used - we use WG values)
            rule_name: Name of rule for logging
            
        Returns:
            Tuple of (source_zone, dest_zone, warnings)
        """
        warnings = []
        
        if not self._inside_zone_ref or not self._outside_zone_ref:
            return None, None, ["Zones not discovered"]
        
        source_zone = self._infer_zone_from_objects(source_objects)
        dest_zone = self._infer_zone_from_objects(dest_objects)
        
        # Record for report
        if source_zone or dest_zone:
            self.report.rules_with_zones += 1
            self.report.zone_inference_details.append({
                "rule": rule_name,
                "source_zone": source_zone["name"] if source_zone else None,
                "dest_zone": dest_zone["name"] if dest_zone else None
            })
        else:
            self.report.rules_without_zones += 1
        
        return source_zone, dest_zone, warnings
    
    def _infer_zone_from_objects(self, objects: List[Dict]) -> Optional[Dict]:
        """
        Infer zone from a list of network objects.
        
        Examines IP values to determine if private (INSIDE) or public (OUTSIDE).
        """
        if not objects:
            return None
        
        private_count = 0
        public_count = 0
        
        for obj_ref in objects:
            obj_name = obj_ref.get('name', '')
            
            # Get IP value from our WatchGuard cache
            ip_value = self._wg_object_values.get(obj_name)
            
            if ip_value:
                is_private = NetworkClassifier.is_private_address(ip_value)
                if is_private is True:
                    private_count += 1
                elif is_private is False:
                    public_count += 1
        
        # Determine zone based on addresses found
        if private_count > 0 and public_count == 0:
            return self._inside_zone_ref
        elif public_count > 0 and private_count == 0:
            return self._outside_zone_ref
        elif private_count > public_count:
            return self._inside_zone_ref
        elif public_count > private_count:
            return self._outside_zone_ref
        
        return None
    
    def is_interface_reference(self, name: str) -> bool:
        """Check if a name refers to an interface (vs a network object).

        NOTE: only meaningful for names that failed object lookup. Bare
        'vpn'/'tunnel' substrings are deliberately NOT matched - WatchGuard
        auto-generates real address objects with names like
        'Allow Servers to SSL VPN.1.from.1.pcy', and matching on 'vpn'
        silently stripped them from rules.
        """
        interface_patterns = [
            "Any-BOVPN", "Any-MUVPN", "Any-External", "Any-Trusted",
            "Any-Optional", "Any-Multicast", "Any", "Firebox"
        ]
        if name in interface_patterns:
            return True

        name_lower = name.lower()
        if any(p in name_lower for p in ["bovpn", "muvpn"]):
            return True

        return False
    
    def get_report(self) -> Dict[str, Any]:
        """Get the zone mapping report."""
        return self.report.to_dict()
    
    def print_summary(self):
        """Print summary of zone mapping."""
        print("\n" + "=" * 60)
        print("ZONE MAPPING SUMMARY")
        print("=" * 60)
        
        print(f"\nFMC Zones: {', '.join(self.report.fmc_zones_found)}")
        
        if self._inside_zone_ref and self._outside_zone_ref:
            print(f"\n✓ Zone inference ready")
            print(f"  Object values loaded: {len(self._wg_object_values)}")
            print(f"  RFC1918/private → {self.inside_zone_name}")
            print(f"  Public/global → {self.outside_zone_name}")
        else:
            print(f"\n⚠ Zone inference not available")