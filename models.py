"""
Data models for WatchGuard and FMC objects.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from enum import Enum


class ObjectType(Enum):
    """FMC object types."""
    HOST = "Host"
    NETWORK = "Network"
    RANGE = "Range"
    FQDN = "FQDN"
    NETWORK_GROUP = "NetworkGroup"
    PORT_OBJECT = "ProtocolPortObject"
    PORT_GROUP = "PortObjectGroup"
    ICMP = "ICMPV4Object"
    URL = "Url"
    URL_GROUP = "UrlGroup"
    APPLICATION = "Application"


@dataclass
class WatchGuardAddress:
    """WatchGuard address object."""
    name: str
    description: str = ""
    
    # Type-specific fields
    ip: Optional[str] = None  # Host
    network: Optional[str] = None  # Network
    mask: Optional[str] = None  # Network
    start: Optional[str] = None  # Range
    end: Optional[str] = None  # Range
    fqdn: Optional[str] = None  # FQDN
    
    @property
    def object_type(self) -> str:
        """Determine object type from fields."""
        if self.ip:
            return "host"
        elif self.network and self.mask:
            return "network"
        elif self.start and self.end:
            return "range"
        elif self.fqdn:
            return "fqdn"
        return "unknown"
    
    @property
    def is_wildcard_fqdn(self) -> bool:
        """Check if this is a wildcard FQDN."""
        return self.fqdn is not None and '*' in self.fqdn


@dataclass
class WatchGuardService:
    """WatchGuard service object."""
    name: str
    protocol: str  # TCP, UDP, ICMP, etc.
    port: Optional[str] = None
    description: str = ""
    
    @property
    def canonical_key(self) -> str:
        """Generate canonical key for deduplication."""
        if self.port:
            return f"{self.protocol}_{self.port}"
        return f"{self.protocol}"


@dataclass
class WatchGuardAddressGroup:
    """WatchGuard address group (alias)."""
    name: str
    description: str = ""
    members: List[str] = field(default_factory=list)
    alias_references: List[str] = field(default_factory=list)
    member_interfaces: List[str] = field(default_factory=list)
    member_types: List[str] = field(default_factory=list)
    member_users: List[str] = field(default_factory=list)
    
    @property
    def is_interface_alias(self) -> bool:
        """Check if this is an interface alias."""
        return len(self.member_interfaces) > 0 and len(self.members) == 0


@dataclass
class WatchGuardPolicy:
    """WatchGuard firewall policy."""
    name: str
    source_members: List[str]
    destination_members: List[str]
    service: str
    action: str  # Allow, Deny, Drop, Proxy
    enabled: bool
    
    # Optional fields
    description: str = ""
    log_enabled: bool = False
    nat_policy: Optional[str] = None
    app_action: Optional[str] = None
    schedule: str = "Always On"
    
    @property
    def has_app_control(self) -> bool:
        """Check if policy has application control."""
        return self.app_action is not None and self.app_action != ""
    
    @property
    def has_nat(self) -> bool:
        """Check if policy has NAT."""
        return self.nat_policy is not None and self.nat_policy != ""


@dataclass
class WatchGuardAppAction:
    """WatchGuard application control policy."""
    name: str
    description: str = ""
    allowed_apps: List[str] = field(default_factory=list)
    blocked_apps: List[str] = field(default_factory=list)
    fallthrough_action: str = "Allow"


@dataclass
class WatchGuardConfig:
    """Complete WatchGuard configuration."""
    hosts: List[WatchGuardAddress] = field(default_factory=list)
    networks: List[WatchGuardAddress] = field(default_factory=list)
    ranges: List[WatchGuardAddress] = field(default_factory=list)
    fqdns: List[WatchGuardAddress] = field(default_factory=list)
    
    address_groups: List[WatchGuardAddressGroup] = field(default_factory=list)
    interface_aliases: List[WatchGuardAddressGroup] = field(default_factory=list)
    
    tcp_services: List[WatchGuardService] = field(default_factory=list)
    udp_services: List[WatchGuardService] = field(default_factory=list)
    icmp_services: List[WatchGuardService] = field(default_factory=list)
    
    policies: List[WatchGuardPolicy] = field(default_factory=list)
    app_actions: List[WatchGuardAppAction] = field(default_factory=list)
    
    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "WatchGuardConfig":
        """Create WatchGuardConfig from parsed JSON."""
        config = cls()
        
        # Parse addresses
        addresses = data.get("addresses", {})
        config.hosts = [WatchGuardAddress(**h) for h in addresses.get("hosts", [])]
        config.networks = [WatchGuardAddress(**n) for n in addresses.get("networks", [])]
        config.ranges = [WatchGuardAddress(**r) for r in addresses.get("ranges", [])]
        config.fqdns = [WatchGuardAddress(**f) for f in addresses.get("fqdns", [])]
        
        # Parse groups
        config.address_groups = [
            WatchGuardAddressGroup(**g) for g in data.get("address_groups", [])
        ]
        config.interface_aliases = [
            WatchGuardAddressGroup(**a) for a in data.get("interface_aliases", [])
        ]
        
        # Parse services
        services = data.get("services", {})
        config.tcp_services = [
            WatchGuardService(protocol="TCP", **s) for s in services.get("tcp", [])
        ]
        config.udp_services = [
            WatchGuardService(protocol="UDP", **s) for s in services.get("udp", [])
        ]
        config.icmp_services = [
            WatchGuardService(protocol="ICMP", **s) for s in services.get("icmp", [])
        ]
        
        # Parse policies
        config.policies = [
            WatchGuardPolicy(
                name=p["name"],
                source_members=p.get("source_members", []),
                destination_members=p.get("destination_members", []),
                service=p.get("service", "Any"),
                action=p.get("action", "Allow"),
                enabled=p.get("enabled", "true") == "true",
                description=p.get("description", ""),
                log_enabled=p.get("log_enabled", "false") == "true",
                nat_policy=p.get("nat_policy"),
                app_action=p.get("app_action"),
                schedule=p.get("schedule", "Always On")
            )
            for p in data.get("policies", [])
        ]
        
        # Parse app actions
        config.app_actions = [
            WatchGuardAppAction(**a) for a in data.get("app_actions", [])
        ]
        
        return config


@dataclass
class FMCObject:
    """FMC object reference."""
    id: str
    name: str
    type: str
    
    # Additional fields for services
    protocol: Optional[str] = None
    port: Optional[str] = None
    
    # Category/tags
    category: Optional[str] = None
    is_builtin: bool = False


@dataclass
class FMCObjects:
    """Collection of FMC objects discovered from API."""
    hosts: Dict[str, FMCObject] = field(default_factory=dict)
    networks: Dict[str, FMCObject] = field(default_factory=dict)
    ranges: Dict[str, FMCObject] = field(default_factory=dict)
    fqdns: Dict[str, FMCObject] = field(default_factory=dict)
    network_groups: Dict[str, FMCObject] = field(default_factory=dict)
    
    port_objects: Dict[str, FMCObject] = field(default_factory=dict)
    port_groups: Dict[str, FMCObject] = field(default_factory=dict)
    icmp_objects: Dict[str, FMCObject] = field(default_factory=dict)
    
    url_objects: Dict[str, FMCObject] = field(default_factory=dict)
    applications: Dict[str, FMCObject] = field(default_factory=dict)
    
    # Canonical mappings: protocol_port -> FMCObject
    canonical_ports: Dict[str, FMCObject] = field(default_factory=dict)
    
    def get_by_name(self, name: str, object_type: str) -> Optional[FMCObject]:
        """Get object by name and type."""
        type_map = {
            "host": self.hosts,
            "network": self.networks,
            "range": self.ranges,
            "fqdn": self.fqdns,
            "network_group": self.network_groups,
            "port": self.port_objects,
            "port_group": self.port_groups,
            "icmp": self.icmp_objects,
            "url": self.url_objects,
            "application": self.applications
        }
        
        obj_dict = type_map.get(object_type, {})
        return obj_dict.get(name)


@dataclass
class MigrationPlan:
    """Complete migration plan mapping WG objects to FMC objects."""
    
    # Object mappings: wg_name -> FMCObject
    address_mappings: Dict[str, FMCObject] = field(default_factory=dict)
    service_mappings: Dict[str, FMCObject] = field(default_factory=dict)
    app_mappings: Dict[str, FMCObject] = field(default_factory=dict)
    
    # Objects to create (don't exist in FMC)
    objects_to_create: List[Dict[str, Any]] = field(default_factory=list)
    
    # Policies to create
    policies_to_create: List[Dict[str, Any]] = field(default_factory=list)
    
    # Issues found
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    # Statistics
    total_wg_objects: int = 0
    mapped_to_existing: int = 0
    needs_creation: int = 0
    unmapped: int = 0
