"""
Data models for WatchGuard and FMC objects.

Updated for v5 parser with service deduplication and service groups.
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
    ICMPV6 = "ICMPV6Object"
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
    """WatchGuard service object.
    
    Updated for v5 parser:
    - original_name: The WatchGuard service name before deduplication
    - name: Unique name for FMC (e.g., PDQ_TCP_139)
    - For single-definition services, name == original_name
    """
    name: str
    protocol: str  # TCP, UDP, ICMP, ICMPv6, GRE, ESP, etc.
    port: Optional[str] = None
    description: str = ""
    original_name: Optional[str] = None  # WatchGuard name before deduplication
    
    # For ICMP services
    icmp_version: Optional[str] = None  # "v4" or "v6"
    
    # For protocol-only services (GRE, ESP, etc.)
    protocol_number: Optional[str] = None
    
    def __post_init__(self):
        """Set original_name to name if not provided."""
        if self.original_name is None:
            self.original_name = self.name
    
    @property
    def canonical_key(self) -> str:
        """Generate canonical key for deduplication."""
        if self.port:
            return f"{self.protocol}_{self.port}"
        return f"{self.protocol}"
    
    @property
    def is_port_based(self) -> bool:
        """Check if this is a TCP/UDP service with a port."""
        return self.protocol in ("TCP", "UDP") and self.port is not None
    
    @property
    def is_icmp(self) -> bool:
        """Check if this is an ICMP service."""
        return self.protocol in ("ICMP", "ICMPv6")
    
    @property
    def is_protocol_only(self) -> bool:
        """Check if this is a protocol-only service (GRE, ESP, etc.)."""
        return self.protocol in ("GRE", "ESP", "AH", "IGMP", "OSPFIGP")


@dataclass
class WatchGuardServiceGroup:
    """WatchGuard service group - created when multiple services share the same name.
    
    FMC Constraints:
    - Port Object Groups can contain TCP and UDP objects mixed together
    - ICMP objects CANNOT be added to port groups
    - Protocol-only objects (GRE, ESP) require special handling
    
    Structure:
    - members: TCP/UDP service names that can go into FMC PortObjectGroup
    - icmp_members: ICMP service names that must be added separately to rules
    - protocol_members: Protocol-only services that use literal protocol numbers
    """
    name: str  # e.g., "PDQ_svc_group"
    original_name: str  # Original WatchGuard service name, e.g., "PDQ"
    description: str = ""
    
    # TCP/UDP members - can be added to FMC PortObjectGroup
    members: List[str] = field(default_factory=list)
    
    # ICMP members - must be added to rules separately (can't be in port groups)
    icmp_members: List[str] = field(default_factory=list)
    
    # Protocol-only members (GRE, ESP) - require special handling
    protocol_members: List[str] = field(default_factory=list)
    
    # Warnings generated during parsing (e.g., unsupported protocols skipped)
    warnings: List[str] = field(default_factory=list)
    
    @property
    def has_tcp_udp(self) -> bool:
        """Check if group has TCP/UDP members."""
        return len(self.members) > 0
    
    @property
    def has_icmp(self) -> bool:
        """Check if group has ICMP members."""
        return len(self.icmp_members) > 0
    
    @property
    def has_protocol_only(self) -> bool:
        """Check if group has protocol-only members."""
        return len(self.protocol_members) > 0
    
    @property
    def total_members(self) -> int:
        """Total count of all member types."""
        return len(self.members) + len(self.icmp_members) + len(self.protocol_members)
    
    @property
    def needs_port_group(self) -> bool:
        """Check if this service group needs an FMC PortObjectGroup."""
        # Only create port group if there are 2+ TCP/UDP members
        return len(self.members) >= 2


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

    # Raw alias names before resolution (v9) - needed by the classifier,
    # since interface aliases like 'Firebox' resolve to no address members.
    source_aliases: List[str] = field(default_factory=list)
    destination_aliases: List[str] = field(default_factory=list)
    
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
    """Complete WatchGuard configuration.
    
    Updated for v5 parser with service groups.
    """
    hosts: List[WatchGuardAddress] = field(default_factory=list)
    networks: List[WatchGuardAddress] = field(default_factory=list)
    ranges: List[WatchGuardAddress] = field(default_factory=list)
    fqdns: List[WatchGuardAddress] = field(default_factory=list)
    
    address_groups: List[WatchGuardAddressGroup] = field(default_factory=list)
    interface_aliases: List[WatchGuardAddressGroup] = field(default_factory=list)
    
    # Services by protocol type
    tcp_services: List[WatchGuardService] = field(default_factory=list)
    udp_services: List[WatchGuardService] = field(default_factory=list)
    icmp_services: List[WatchGuardService] = field(default_factory=list)
    protocol_only_services: List[WatchGuardService] = field(default_factory=list)  # GRE, ESP, etc.
    other_services: List[WatchGuardService] = field(default_factory=list)  # Unsupported
    
    # Service groups (new in v5)
    service_groups: List[WatchGuardServiceGroup] = field(default_factory=list)
    
    policies: List[WatchGuardPolicy] = field(default_factory=list)
    app_actions: List[WatchGuardAppAction] = field(default_factory=list)
    
    # Lookup caches (built on demand)
    _service_lookup: Optional[Dict[str, Any]] = field(default=None, repr=False)
    
    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "WatchGuardConfig":
        """Create WatchGuardConfig from parsed JSON (v5 format)."""
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
        
        # Parse services (v5 format with original_name)
        services = data.get("services", {})
        
        # Helper to build WatchGuardService from JSON
        def make_service(s: Dict, default_protocol: str) -> WatchGuardService:
            return WatchGuardService(
                name=s.get("name", ""),
                protocol=s.get("protocol", default_protocol),
                port=s.get("port"),
                description=s.get("description", ""),
                original_name=s.get("original_name"),
                icmp_version=s.get("icmp_version"),
                protocol_number=s.get("protocol_number")
            )
        
        config.tcp_services = [make_service(s, "TCP") for s in services.get("tcp", [])]
        config.udp_services = [make_service(s, "UDP") for s in services.get("udp", [])]
        config.icmp_services = [make_service(s, "ICMP") for s in services.get("icmp", [])]
        config.protocol_only_services = [make_service(s, "") for s in services.get("protocol_only", [])]
        config.other_services = [make_service(s, "") for s in services.get("other", [])]
        
        # Parse service groups (new in v5)
        config.service_groups = [
            WatchGuardServiceGroup(
                name=g.get("name", ""),
                original_name=g.get("original_name", ""),
                description=g.get("description", ""),
                members=g.get("members", []),
                icmp_members=g.get("icmp_members", []),
                protocol_members=g.get("protocol_members", []),
                warnings=g.get("warnings", [])
            )
            for g in data.get("service_groups", [])
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
                schedule=p.get("schedule", "Always On"),
                source_aliases=p.get("source_aliases", []),
                destination_aliases=p.get("destination_aliases", [])
            )
            for p in data.get("policies", [])
        ]
        
        # Parse app actions
        config.app_actions = [
            WatchGuardAppAction(**a) for a in data.get("app_actions", [])
        ]
        
        return config
    
    def build_service_lookup(self) -> Dict[str, Any]:
        """
        Build lookup structure for service resolution.
        
        Returns dict with:
        - by_original_name: Maps original WG name -> service group OR individual service
        - by_unique_name: Maps unique FMC name -> service object
        - service_groups: Maps group name -> WatchGuardServiceGroup
        """
        if self._service_lookup is not None:
            return self._service_lookup
        
        lookup = {
            "by_original_name": {},
            "by_unique_name": {},
            "service_groups": {}
        }
        
        # First, index all service groups by original name
        for group in self.service_groups:
            lookup["by_original_name"][group.original_name] = {
                "type": "group",
                "group": group
            }
            lookup["service_groups"][group.name] = group
        
        # Then, index individual services
        all_services = [
            ("tcp", self.tcp_services),
            ("udp", self.udp_services),
            ("icmp", self.icmp_services),
            ("protocol_only", self.protocol_only_services),
            ("other", self.other_services)
        ]
        
        for svc_type, services in all_services:
            for svc in services:
                # Index by unique name
                lookup["by_unique_name"][svc.name] = {
                    "type": svc_type,
                    "service": svc
                }
                
                # For original names NOT in a group, also index by original name
                original = svc.original_name or svc.name
                if original not in lookup["by_original_name"]:
                    lookup["by_original_name"][original] = {
                        "type": svc_type,
                        "service": svc
                    }
        
        self._service_lookup = lookup
        return lookup
    
    def resolve_service(self, service_name: str) -> Dict[str, Any]:
        """
        Resolve a WatchGuard service name to either a service group or individual service.
        
        Args:
            service_name: The original WatchGuard service name from a policy
            
        Returns:
            Dict with 'type' key:
            - type='group': group=WatchGuardServiceGroup
            - type='tcp'|'udp'|'icmp'|etc: service=WatchGuardService
            - type='not_found': if service doesn't exist
        """
        lookup = self.build_service_lookup()
        
        if service_name in lookup["by_original_name"]:
            return lookup["by_original_name"][service_name]
        
        return {"type": "not_found", "name": service_name}
    
    def get_service_by_unique_name(self, unique_name: str) -> Optional[WatchGuardService]:
        """Get a service by its unique FMC-compatible name."""
        lookup = self.build_service_lookup()
        
        result = lookup["by_unique_name"].get(unique_name)
        if result:
            return result.get("service")
        return None
    
    @property
    def all_services(self) -> List[WatchGuardService]:
        """Get all services across all protocol types."""
        return (
            self.tcp_services + 
            self.udp_services + 
            self.icmp_services + 
            self.protocol_only_services + 
            self.other_services
        )


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
    
    # Service group mappings: group_name -> FMCObject (PortObjectGroup)
    service_group_mappings: Dict[str, FMCObject] = field(default_factory=dict)
    
    # Objects to create (don't exist in FMC)
    objects_to_create: List[Dict[str, Any]] = field(default_factory=list)
    
    # Service groups to create
    service_groups_to_create: List[WatchGuardServiceGroup] = field(default_factory=list)
    
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
