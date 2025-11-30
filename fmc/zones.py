"""
FMC Security Zone Discovery and WatchGuard Interface Mapping.

This module provides:
1. Discovery of existing FMC security zones
2. Parsing and classification of WatchGuard interfaces
3. Mapping WatchGuard interfaces to FMC zones based on IP addressing

Zone Mapping Rules:
- RFC1918 addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x) → INSIDE zone
- Non-RFC1918 addresses → OUTSIDE zone
- No IP address or unclear → Logged for manual intervention

This does NOT create interfaces or zones on the FTD - it only maps
WatchGuard interfaces to existing FMC zones for rule creation.
"""

import ipaddress
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from models import FMCObject


@dataclass
class WatchGuardInterface:
    """Parsed WatchGuard interface configuration."""
    name: str
    device_name: str  # e.g., "eth0", "eth8"
    ip: Optional[str] = None
    gateway: Optional[str] = None
    mask: Optional[str] = None
    enabled: bool = True
    description: str = ""
    node_type: str = ""  # e.g., "IP4_ONLY"
    secondary_ips: List[str] = field(default_factory=list)
    
    # Derived classification
    zone_classification: Optional[str] = None  # "INSIDE", "OUTSIDE", or None
    classification_reason: str = ""
    
    @property
    def has_ip(self) -> bool:
        """Check if interface has an IP address configured."""
        return self.ip is not None and self.ip != ""
    
    @property
    def is_loopback(self) -> bool:
        """Check if this is a loopback address."""
        if not self.ip:
            return False
        try:
            addr = ipaddress.ip_address(self.ip)
            return addr.is_loopback
        except ValueError:
            return False


@dataclass
class InterfaceMappingResult:
    """Result of interface-to-zone mapping."""
    wg_interface: str
    ip: Optional[str]
    zone: Optional[str]
    zone_id: Optional[str] = None
    reason: str = ""
    
    @property
    def is_mapped(self) -> bool:
        return self.zone is not None and self.zone_id is not None


@dataclass
class ZoneMappingReport:
    """Complete interface mapping report for migration_report.json."""
    fmc_zones_found: List[str] = field(default_factory=list)
    fmc_zone_ids: Dict[str, str] = field(default_factory=dict)
    mapped: List[Dict[str, Any]] = field(default_factory=list)
    unmapped: List[Dict[str, Any]] = field(default_factory=list)
    missing_zones: List[str] = field(default_factory=list)
    interface_aliases: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "fmc_zones_found": self.fmc_zones_found,
            "mapped": self.mapped,
            "unmapped": self.unmapped,
            "missing_zones": self.missing_zones,
            "interface_aliases": self.interface_aliases
        }


class InterfaceClassifier:
    """Classifies WatchGuard interfaces based on IP addressing."""
    
    # RFC1918 private address ranges
    RFC1918_RANGES = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    ]
    
    # Additional private/internal ranges
    INTERNAL_RANGES = [
        ipaddress.ip_network("100.64.0.0/10"),    # CGNAT
        ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ]
    
    # Known VPN/tunnel interface patterns (no IP typically)
    VPN_INTERFACE_PATTERNS = [
        "bovpn", "muvpn", "vpn", "tunnel", "ipsec", "ssl",
        "ikev2", "l2tp", "pptp", "gre"
    ]
    
    # Known external/WAN interface patterns
    EXTERNAL_PATTERNS = [
        "external", "wan", "internet", "outside", "untrust"
    ]
    
    # Known internal/LAN interface patterns
    INTERNAL_PATTERNS = [
        "internal", "lan", "inside", "trust", "trusted", "optional",
        "dmz", "corp", "corporate"
    ]
    
    @classmethod
    def is_rfc1918(cls, ip_str: str) -> bool:
        """Check if an IP address is RFC1918 private."""
        try:
            addr = ipaddress.ip_address(ip_str)
            for network in cls.RFC1918_RANGES:
                if addr in network:
                    return True
            return False
        except ValueError:
            return False
    
    @classmethod
    def is_private(cls, ip_str: str) -> bool:
        """Check if an IP address is private (RFC1918 or other internal ranges)."""
        try:
            addr = ipaddress.ip_address(ip_str)
            # Use Python's built-in check
            return addr.is_private
        except ValueError:
            return False
    
    @classmethod
    def classify_by_ip(cls, ip_str: str) -> Tuple[str, str]:
        """
        Classify an IP address as INSIDE or OUTSIDE.
        
        Returns:
            Tuple of (zone, reason)
        """
        if not ip_str:
            return (None, "No IP address configured")
        
        try:
            addr = ipaddress.ip_address(ip_str)
            
            if addr.is_loopback:
                return (None, "Loopback address - skip")
            
            if addr.is_link_local:
                return ("INSIDE", f"Link-local address ({ip_str})")
            
            # Check RFC1918 specifically
            for network in cls.RFC1918_RANGES:
                if addr in network:
                    return ("INSIDE", f"RFC1918 address ({ip_str})")
            
            # Check other private ranges (CGNAT, etc.)
            if addr.is_private:
                return ("INSIDE", f"Private address ({ip_str})")
            
            # Public/global address
            if addr.is_global:
                return ("OUTSIDE", f"Public address ({ip_str})")
            
            return (None, f"Unclassifiable address ({ip_str})")
            
        except ValueError as e:
            return (None, f"Invalid IP address: {e}")
    
    @classmethod
    def classify_by_name(cls, name: str) -> Tuple[Optional[str], str]:
        """
        Attempt to classify interface by name patterns.
        Used as fallback when no IP is available.
        
        Returns:
            Tuple of (zone_hint, reason)
        """
        name_lower = name.lower()
        
        # Check for VPN patterns
        for pattern in cls.VPN_INTERFACE_PATTERNS:
            if pattern in name_lower:
                return (None, f"VPN/tunnel interface pattern '{pattern}' - requires manual mapping")
        
        # Check for external patterns
        for pattern in cls.EXTERNAL_PATTERNS:
            if pattern in name_lower:
                return ("OUTSIDE", f"Name contains external pattern '{pattern}'")
        
        # Check for internal patterns
        for pattern in cls.INTERNAL_PATTERNS:
            if pattern in name_lower:
                return ("INSIDE", f"Name contains internal pattern '{pattern}'")
        
        return (None, "Could not determine zone from interface name")
    
    @classmethod
    def classify_interface(cls, interface: WatchGuardInterface) -> WatchGuardInterface:
        """
        Classify a WatchGuard interface and update its zone_classification.
        
        Priority:
        1. IP-based classification (most reliable)
        2. Name-based classification (fallback)
        """
        # First try IP-based classification
        if interface.has_ip:
            zone, reason = cls.classify_by_ip(interface.ip)
            interface.zone_classification = zone
            interface.classification_reason = reason
            return interface
        
        # Fallback to name-based classification
        zone_hint, reason = cls.classify_by_name(interface.name)
        interface.zone_classification = zone_hint
        interface.classification_reason = reason
        
        return interface


class ZoneMapper:
    """
    Maps WatchGuard interfaces to FMC security zones.
    
    This class:
    1. Discovers existing FMC security zones
    2. Parses WatchGuard interface configurations
    3. Classifies interfaces as INSIDE or OUTSIDE
    4. Provides zone references for rule creation
    """
    
    # Expected zone names (can be configured)
    EXPECTED_ZONES = ["INSIDE", "OUTSIDE"]
    
    def __init__(self, fmc_client):
        """
        Initialize ZoneMapper.
        
        Args:
            fmc_client: Authenticated FMCClient instance
        """
        self.fmc = fmc_client
        self.fmc_zones: Dict[str, FMCObject] = {}
        self.wg_interfaces: Dict[str, WatchGuardInterface] = {}
        self.interface_to_zone: Dict[str, InterfaceMappingResult] = {}
        self.report = ZoneMappingReport()
        
        # Track interface aliases (groups that contain interface references)
        self.interface_aliases: Dict[str, List[str]] = {}
    
    def discover_fmc_zones(self) -> bool:
        """
        Discover existing security zones in FMC.
        
        Returns:
            True if expected zones exist, False otherwise
        """
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
            self.report.fmc_zone_ids[item['name']] = item['id']
        
        self.report.fmc_zones_found = list(self.fmc_zones.keys())
        
        print(f"  Found {len(self.fmc_zones)} security zones: {', '.join(self.fmc_zones.keys())}")
        
        # Check for expected zones
        missing = []
        for expected in self.EXPECTED_ZONES:
            # Case-insensitive check
            found = False
            for zone_name in self.fmc_zones.keys():
                if zone_name.upper() == expected.upper():
                    found = True
                    break
            if not found:
                missing.append(expected)
        
        if missing:
            self.report.missing_zones = missing
            print(f"  ⚠ Missing expected zones: {', '.join(missing)}")
            return False
        
        print(f"  ✓ Expected zones INSIDE and OUTSIDE are available")
        return True
    
    def parse_wg_interfaces(self, wg_config_data: Dict[str, Any]) -> int:
        """
        Parse WatchGuard interface configurations from parsed config JSON.
        
        Args:
            wg_config_data: Raw WatchGuard config dict (from JSON)
            
        Returns:
            Number of interfaces parsed
        """
        interfaces = wg_config_data.get("interfaces", [])
        
        if not interfaces:
            print("  ⚠ No interfaces found in WatchGuard config")
            return 0
        
        print(f"\n  Parsing {len(interfaces)} WatchGuard interfaces...")
        
        for iface_data in interfaces:
            iface = WatchGuardInterface(
                name=iface_data.get("name", ""),
                device_name=iface_data.get("device_name", ""),
                ip=iface_data.get("ip"),
                gateway=iface_data.get("gateway"),
                mask=iface_data.get("mask"),
                enabled=iface_data.get("enabled", "1") == "1",
                description=iface_data.get("description", ""),
                node_type=iface_data.get("node_type", ""),
                secondary_ips=iface_data.get("secondary_ips", [])
            )
            
            # Classify the interface
            InterfaceClassifier.classify_interface(iface)
            self.wg_interfaces[iface.name] = iface
        
        print(f"  ✓ Parsed {len(self.wg_interfaces)} interfaces")
        return len(self.wg_interfaces)
    
    def parse_interface_aliases(self, wg_config_data: Dict[str, Any]):
        """
        Identify address groups that are interface aliases.
        
        These are groups whose members are interface names, not network objects.
        They need special handling during group creation and rule mapping.
        
        Args:
            wg_config_data: Raw WatchGuard config dict
        """
        interface_aliases = wg_config_data.get("interface_aliases", [])
        
        if not interface_aliases:
            print("  No explicit interface aliases found")
            return
        
        print(f"\n  Parsing {len(interface_aliases)} interface aliases...")
        
        for alias in interface_aliases:
            name = alias.get("name", "")
            # member_interfaces contains the actual interface references
            members = alias.get("member_interfaces", [])
            
            if name and members:
                self.interface_aliases[name] = members
                self.report.interface_aliases.append({
                    "name": name,
                    "interfaces": members,
                    "note": "Interface alias - not a network object group"
                })
        
        print(f"  ✓ Found {len(self.interface_aliases)} interface aliases")
    
    def build_zone_mappings(self) -> int:
        """
        Build the interface-to-zone mapping table.
        
        Returns:
            Number of successfully mapped interfaces
        """
        print("\n  Building interface-to-zone mappings...")
        
        mapped_count = 0
        unmapped_count = 0
        
        for name, iface in self.wg_interfaces.items():
            # Determine target zone
            target_zone = iface.zone_classification
            
            if target_zone and target_zone in self.fmc_zones:
                zone_obj = self.fmc_zones[target_zone]
                result = InterfaceMappingResult(
                    wg_interface=name,
                    ip=iface.ip,
                    zone=target_zone,
                    zone_id=zone_obj.id,
                    reason=iface.classification_reason
                )
                self.interface_to_zone[name] = result
                self.report.mapped.append({
                    "wg_interface": name,
                    "device": iface.device_name,
                    "ip": iface.ip,
                    "zone": target_zone,
                    "reason": iface.classification_reason
                })
                mapped_count += 1
            else:
                # Could not map
                result = InterfaceMappingResult(
                    wg_interface=name,
                    ip=iface.ip,
                    zone=None,
                    zone_id=None,
                    reason=iface.classification_reason
                )
                self.interface_to_zone[name] = result
                self.report.unmapped.append({
                    "wg_interface": name,
                    "device": iface.device_name,
                    "ip": iface.ip,
                    "reason": iface.classification_reason
                })
                unmapped_count += 1
        
        print(f"  ✓ Mapped {mapped_count} interfaces to zones")
        if unmapped_count > 0:
            print(f"  ⚠ {unmapped_count} interfaces could not be mapped")
        
        return mapped_count
    
    def get_zone_for_interface(self, interface_name: str) -> Optional[Dict[str, str]]:
        """
        Get the FMC zone reference for a WatchGuard interface.
        
        Args:
            interface_name: WatchGuard interface name
            
        Returns:
            Dict with zone reference for FMC API, or None if not mapped
            Example: {"name": "INSIDE", "id": "uuid...", "type": "SecurityZone"}
        """
        result = self.interface_to_zone.get(interface_name)
        
        if result and result.is_mapped:
            return {
                "name": result.zone,
                "id": result.zone_id,
                "type": "SecurityZone"
            }
        
        return None
    
    def is_interface_reference(self, name: str) -> bool:
        """
        Check if a name refers to an interface (vs a network object).
        
        Args:
            name: Object/interface name from WatchGuard config
            
        Returns:
            True if this is an interface name
        """
        # Direct interface match
        if name in self.wg_interfaces:
            return True
        
        # Interface alias match
        if name in self.interface_aliases:
            return True
        
        # Check common interface alias patterns
        interface_patterns = [
            "Any-BOVPN", "Any-MUVPN", "Any-External", "Any-Trusted", 
            "Any-Optional", "Any-Multicast"
        ]
        if name in interface_patterns:
            return True
        
        return False
    
    def get_zones_for_interfaces(self, interface_names: List[str]) -> Tuple[List[Dict], List[str]]:
        """
        Get FMC zone references for a list of WatchGuard interface names.
        
        Args:
            interface_names: List of interface names from a rule
            
        Returns:
            Tuple of (zone_objects, warnings)
            - zone_objects: List of FMC zone references
            - warnings: List of warning messages for unmapped interfaces
        """
        zones = []
        warnings = []
        seen_zones = set()  # Avoid duplicates
        
        for name in interface_names:
            # Skip "Any" - means any zone
            if name in ["Any", "Any-External", "Any-Trusted", "Any-Optional"]:
                continue
            
            zone_ref = self.get_zone_for_interface(name)
            
            if zone_ref:
                zone_key = zone_ref["id"]
                if zone_key not in seen_zones:
                    zones.append(zone_ref)
                    seen_zones.add(zone_key)
            else:
                # Check if it's an interface alias
                if name in self.interface_aliases:
                    # Get zones for the interfaces in this alias
                    alias_interfaces = self.interface_aliases[name]
                    for iface in alias_interfaces:
                        zone_ref = self.get_zone_for_interface(iface)
                        if zone_ref:
                            zone_key = zone_ref["id"]
                            if zone_key not in seen_zones:
                                zones.append(zone_ref)
                                seen_zones.add(zone_key)
                        else:
                            warnings.append(
                                f"Interface alias '{name}' member '{iface}' has no zone mapping"
                            )
                elif self.is_interface_reference(name):
                    warnings.append(f"Interface '{name}' has no zone mapping")
                # If not an interface reference, it's probably a network object - ignore here
        
        return zones, warnings
    
    def get_report(self) -> Dict[str, Any]:
        """Get the interface mapping report for migration_report.json."""
        return self.report.to_dict()
    
    def print_summary(self):
        """Print a summary of interface mapping."""
        print("\n" + "=" * 60)
        print("INTERFACE TO ZONE MAPPING SUMMARY")
        print("=" * 60)
        
        print(f"\nFMC Zones: {len(self.fmc_zones)}")
        for name in self.fmc_zones:
            print(f"  - {name}")
        
        if self.report.missing_zones:
            print(f"\n⚠ Missing expected zones: {', '.join(self.report.missing_zones)}")
        
        print(f"\nWatchGuard Interfaces: {len(self.wg_interfaces)}")
        print(f"  Mapped to zones: {len(self.report.mapped)}")
        print(f"  Unmapped: {len(self.report.unmapped)}")
        
        if self.interface_aliases:
            print(f"\nInterface Aliases: {len(self.interface_aliases)}")
        
        if self.report.unmapped:
            print("\nUnmapped Interfaces (require manual review):")
            for entry in self.report.unmapped[:10]:  # Show first 10
                print(f"  - {entry['wg_interface']}: {entry['reason']}")
            if len(self.report.unmapped) > 10:
                print(f"  ... and {len(self.report.unmapped) - 10} more")
