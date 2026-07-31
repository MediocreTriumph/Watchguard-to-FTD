"""
Migration Planner - Creates migration plan with proper alias resolution.

Updated for v5 parser with service group support.
Updated for v7 with user mapping support.
"""

from typing import Dict, List, Set, Any, Optional, Tuple
from dataclasses import dataclass, field
import json
from models import (
    WatchGuardConfig, WatchGuardPolicy, WatchGuardAddress,
    WatchGuardAddressGroup, WatchGuardService, WatchGuardServiceGroup,
    WatchGuardAppAction, FMCObject
)
from .classifier import split_policies, classify_policy


@dataclass  
class MigrationPlan:
    """Complete migration plan."""
    address_mappings: Dict[str, FMCObject]
    service_mappings: Dict[str, FMCObject]
    application_mappings: Dict[str, FMCObject]
    objects_to_create: List[Dict]
    policies_to_create: List[Dict]
    statistics: Dict[str, int]
    
    # Service group support (v5)
    service_groups_to_create: List[WatchGuardServiceGroup] = field(default_factory=list)

    # Policy classification (v9): policies excluded from migration, with reasons
    skipped_policies: List[Dict] = field(default_factory=list)
    
    @property
    def total_wg_objects(self):
        return self.statistics.get('total_wg_objects', 0)
    
    @property
    def mapped_to_existing(self):
        return self.statistics.get('mapped_to_existing', 0)
    
    @property
    def needs_creation(self):
        return self.statistics.get('needs_creation', 0)
    
    @property
    def unmapped(self):
        return self.statistics.get('unmapped', 0)
    
    @property
    def total_policies(self):
        return self.statistics.get('total_policies', 0)
    
    @property
    def policies_with_warnings(self):
        return self.statistics.get('policies_with_warnings', 0)
    
    @property
    def policies_with_errors(self):
        return self.statistics.get('policies_with_errors', 0)
    
    @property
    def app_mappings(self):
        """Alias for application_mappings for CLI compatibility."""
        return self.application_mappings
    
    @property
    def warnings(self) -> List[str]:
        """Aggregate all warnings from policies_to_create."""
        all_warnings = []
        for policy in self.policies_to_create:
            policy_warnings = policy.get('warnings', [])
            policy_name = policy.get('wg_policy', 'Unknown')
            for warning in policy_warnings:
                all_warnings.append(f"[{policy_name}] {warning}")
        return all_warnings
    
    @property
    def errors(self) -> List[str]:
        """Aggregate all errors from policies_to_create."""
        all_errors = []
        for policy in self.policies_to_create:
            policy_errors = policy.get('errors', [])
            policy_name = policy.get('wg_policy', 'Unknown')
            for error in policy_errors:
                all_errors.append(f"[{policy_name}] {error}")
        return all_errors


class MigrationPlanner:
    """Plans migration from WatchGuard to FMC with proper alias resolution."""
    
    def __init__(self, wg_config: WatchGuardConfig, fmc_discovery,
                 service_mapper, app_mapper, user_mapper=None,
                 include_management: bool = False):
        self.wg_config = wg_config
        self.fmc_discovery = fmc_discovery
        self.service_mapper = service_mapper
        self.app_mapper = app_mapper
        self.user_mapper = user_mapper  # v7: optional user mapper
        self.include_management = include_management  # v9: classification override
        self._build_lookups()
    
    def _is_host_mask(self, mask: str) -> bool:
        """Check if a mask represents a single host (/32)."""
        return mask in ['255.255.255.255', '32', '/32']
    
    def _is_wildcard_fqdn(self, wg_obj: WatchGuardAddress) -> bool:
        """Check if an FQDN object contains wildcards (should be URL object)."""
        if wg_obj.object_type != 'fqdn':
            return False
        if not hasattr(wg_obj, 'fqdn') or not wg_obj.fqdn:
            return False
        return '*' in wg_obj.fqdn or wg_obj.fqdn.startswith('.')
    
    def _get_actual_type(self, wg_obj: WatchGuardAddress) -> str:
        """
        Get the actual FMC type for an object, accounting for:
        - Networks with /32 mask -> Host
        - Wildcard FQDNs -> Url
        """
        obj_type = wg_obj.object_type
        
        # Check if this "network" is actually a host (/32 mask)
        if obj_type == 'network' and hasattr(wg_obj, 'mask') and wg_obj.mask:
            if self._is_host_mask(wg_obj.mask):
                return 'host'
        
        # Check if this FQDN is a wildcard (-> URL)
        if obj_type == 'fqdn' and self._is_wildcard_fqdn(wg_obj):
            return 'url'
        
        return obj_type
    
    def _build_lookups(self):
        """Build lookup structures."""
        self.address_objects = {}
        self.wildcard_fqdns = set()  # Track which FQDNs are wildcards
        self.host_networks = set()   # Track which networks are actually /32 hosts
        
        for host in self.wg_config.hosts:
            self.address_objects[host.name] = host
        
        for network in self.wg_config.networks:
            self.address_objects[network.name] = network
            # Track /32 networks that should be hosts
            if hasattr(network, 'mask') and network.mask and self._is_host_mask(network.mask):
                self.host_networks.add(network.name)
        
        for range_obj in self.wg_config.ranges:
            self.address_objects[range_obj.name] = range_obj
        
        for fqdn in self.wg_config.fqdns:
            self.address_objects[fqdn.name] = fqdn
            # Track wildcards
            if self._is_wildcard_fqdn(fqdn):
                self.wildcard_fqdns.add(fqdn.name)
        
        self.address_groups = {g.name: g for g in self.wg_config.address_groups}
        
        # =====================================================================
        # Service lookups (updated for v5 with service groups)
        # =====================================================================
        
        # Individual services by unique name (e.g., "PDQ_TCP_139")
        self.services_by_name: Dict[str, WatchGuardService] = {}
        
        # Service groups by original name (e.g., "PDQ" -> WatchGuardServiceGroup)
        self.service_groups_by_original: Dict[str, WatchGuardServiceGroup] = {}
        
        # Map original service name -> group name OR individual service name
        # This is the primary lookup for policy resolution
        self.service_lookup: Dict[str, Dict[str, Any]] = {}
        
        # First, index service groups by their original name
        for group in self.wg_config.service_groups:
            self.service_groups_by_original[group.original_name] = group
            self.service_lookup[group.original_name] = {
                'type': 'group',
                'group': group
            }
        
        # Index all individual services by unique name
        all_services = (
            self.wg_config.tcp_services +
            self.wg_config.udp_services +
            self.wg_config.icmp_services +
            getattr(self.wg_config, 'protocol_only_services', []) +
            getattr(self.wg_config, 'other_services', [])
        )
        
        for svc in all_services:
            self.services_by_name[svc.name] = svc
            
            # For services NOT part of a group, also index by original_name
            original = svc.original_name or svc.name
            if original not in self.service_lookup:
                self.service_lookup[original] = {
                    'type': 'service',
                    'service': svc
                }
        
        # Legacy: flat services dict for backward compatibility
        self.services = {}
        for tcp in self.wg_config.tcp_services:
            # Use original_name for policy lookup compatibility
            original = tcp.original_name or tcp.name
            if original not in self.service_groups_by_original:
                self.services[original] = tcp
        for udp in self.wg_config.udp_services:
            original = udp.original_name or udp.name
            if original not in self.service_groups_by_original:
                self.services[original] = udp
        
        # URL objects list for creation
        self.url_objects = []
        for fqdn in self.wg_config.fqdns:
            if self._is_wildcard_fqdn(fqdn):
                self.url_objects.append({
                    'name': fqdn.name,
                    'url': fqdn.fqdn,
                    'description': fqdn.description
                })
        
        # Build app_actions lookup by name
        self.app_actions = {aa.name: aa for aa in self.wg_config.app_actions}
        
        print(f"  Identified {len(self.wildcard_fqdns)} wildcard FQDNs (will be URL objects)")
        print(f"  Identified {len(self.host_networks)} /32 networks (will be Host objects)")
        print(f"  Loaded {len(self.app_actions)} application action definitions")
        print(f"  Indexed {len(self.services_by_name)} individual services")
        print(f"  Indexed {len(self.service_groups_by_original)} service groups")
    
    def _get_app_action_by_name(self, name: str) -> Optional[WatchGuardAppAction]:
        """Look up an app_action by name."""
        return self.app_actions.get(name)
    
    def resolve_alias_to_objects(self, alias_name: str, visited: Optional[Set[str]] = None) -> List[str]:
        """Recursively resolve alias to address object names."""
        if visited is None:
            visited = set()
        
        if alias_name in visited:
            return []
        visited.add(alias_name)
        
        if alias_name in ["Any", "Any-External", "Any-Trusted", "Any-Optional"]:
            return []
        
        if alias_name in self.address_objects:
            return [alias_name]
        
        if alias_name not in self.address_groups:
            return []
        
        group = self.address_groups[alias_name]
        resolved = []
        
        for member in group.members:
            if member in self.address_objects:
                resolved.append(member)
        
        for alias_ref in group.alias_references:
            resolved.extend(self.resolve_alias_to_objects(alias_ref, visited))
        
        return list(set(resolved))
    
    def resolve_alias_to_users(self, alias_name: str, visited: Optional[Set[str]] = None) -> List[str]:
        """
        Recursively resolve alias to user names.
        
        Args:
            alias_name: Name of the alias/group to resolve
            visited: Set of already-visited aliases (for cycle detection)
            
        Returns:
            List of WatchGuard user strings (e.g., "DOMAIN\\username")
        """
        if visited is None:
            visited = set()
        
        if alias_name in visited:
            return []
        visited.add(alias_name)
        
        if alias_name in ["Any", "Any-External", "Any-Trusted", "Any-Optional"]:
            return []
        
        if alias_name not in self.address_groups:
            return []
        
        group = self.address_groups[alias_name]
        resolved = []
        
        # Get direct user members
        if group.member_users:
            resolved.extend(group.member_users)
        
        # Recursively resolve alias references
        for alias_ref in group.alias_references:
            resolved.extend(self.resolve_alias_to_users(alias_ref, visited))
        
        return list(set(resolved))
    
    def resolve_service(self, service_name: str) -> Dict[str, Any]:
        """
        Resolve a WatchGuard service name to either a service group or individual service.
        
        Returns:
            Dict with 'type' key:
            - type='group': Contains 'group' (WatchGuardServiceGroup)
            - type='service': Contains 'service' (WatchGuardService)
            - type='not_found': Service doesn't exist
        """
        if service_name in self.service_lookup:
            return self.service_lookup[service_name]
        return {'type': 'not_found', 'name': service_name}
    
    def _get_app_mappings(self) -> Dict[str, FMCObject]:
        """Get application mappings from app_mapper."""
        if hasattr(self.app_mapper, 'app_mappings'):
            return self.app_mapper.app_mappings
        elif hasattr(self.app_mapper, 'mappings'):
            return self.app_mapper.mappings
        elif hasattr(self.app_mapper, 'application_mappings'):
            return self.app_mapper.application_mappings
        else:
            print("  Warning: ApplicationMapper has no mappings attribute")
            for attr in dir(self.app_mapper):
                if not attr.startswith('_'):
                    val = getattr(self.app_mapper, attr)
                    if isinstance(val, dict) and len(val) > 0:
                        first_val = next(iter(val.values()), None)
                        if hasattr(first_val, 'id') and hasattr(first_val, 'name'):
                            print(f"  Found mappings in '{attr}' attribute")
                            return val
            return {}
    
    def _get_service_mappings(self) -> Dict[str, FMCObject]:
        """Get service mappings from service_mapper."""
        if hasattr(self.service_mapper, 'service_mappings'):
            return self.service_mapper.service_mappings
        elif hasattr(self.service_mapper, 'mappings'):
            return self.service_mapper.mappings
        else:
            print("  Warning: ServiceMapper has no mappings attribute")
            return {}
    
    def build_plan(self) -> MigrationPlan:
        """Build migration plan."""
        print("\n" + "="*60)
        print("BUILDING MIGRATION PLAN")
        print("="*60)
        
        address_mappings = {}
        
        service_mappings = self._get_service_mappings()
        application_mappings = self._get_app_mappings()
        
        print(f"\n  Service mappings found: {len(service_mappings)}")
        print(f"  Application mappings found: {len(application_mappings)}")
        
        objects_to_create = []
        policies_to_create = []
        service_groups_to_create = []
        
        print("\nMapping address objects...")
        for name, obj in self.address_objects.items():
            # Use actual type (accounting for /32 hosts and wildcard URLs)
            actual_type = self._get_actual_type(obj)
            objects_to_create.append({'type': actual_type, 'wg_object': obj})
        
        print("\nMapping services...")
        # Add individual services that need creation
        for name, svc in self.services_by_name.items():
            # Check if this service (by its unique name) already exists via canonical mapping
            if name not in service_mappings:
                # Also check by original name
                original = svc.original_name or name
                if original not in service_mappings:
                    objects_to_create.append({'type': 'service', 'wg_object': svc})
        
        print("\nMapping service groups...")
        # Add service groups that need creation
        for original_name, group in self.service_groups_by_original.items():
            if group.needs_port_group:
                service_groups_to_create.append(group)
        
        print(f"  Service groups to create: {len(service_groups_to_create)}")
        
        print("\nProcessing URL objects...")
        print(f"  Found {len(self.url_objects)} wildcard URLs to create as URL objects")
        
        print("\nIdentifying objects to create...")
        print(f"  Objects to create: {len(objects_to_create)}")
        
        for group in self.wg_config.address_groups:
            objects_to_create.append({'type': 'address_group', 'wg_object': group})
        
        print("\nClassifying policies...")
        policies_to_migrate, skipped_policies = split_policies(
            self.wg_config.policies, include_management=self.include_management
        )
        skipped_count = sum(1 for s in skipped_policies if not s.get('included'))
        included_nontraffic = sum(1 for s in skipped_policies if s.get('included'))
        print(f"  Traffic policies: {len(policies_to_migrate) - included_nontraffic}")
        if skipped_count:
            print(f"  Skipped (management-plane/default-deny): {skipped_count}")
            for s in skipped_policies:
                if not s.get('included'):
                    print(f"    - [{s['classification']}] {s['name']}: {s['reason']}")
        if included_nontraffic:
            print(f"  Non-traffic policies INCLUDED via --include-management: {included_nontraffic}")

        print("\nPlanning policy migration...")
        policies_with_issues = 0
        policies_with_warnings = 0
        policies_with_apps = 0
        policies_with_service_groups = 0
        policies_with_users = 0

        for policy in policies_to_migrate:
            policy_plan, issues = self._plan_policy(policy, address_mappings,
                                                    service_mappings, application_mappings)
            policy_plan['classification'] = classify_policy(policy)
            if issues:
                policies_with_issues += 1
            if policy_plan.get('warnings'):
                policies_with_warnings += 1
            if policy_plan.get('fmc_rule', {}).get('applications'):
                policies_with_apps += 1
            if policy_plan.get('uses_service_group'):
                policies_with_service_groups += 1
            if policy_plan.get('users_resolved'):
                policies_with_users += 1
            policies_to_create.append(policy_plan)
        
        print(f"  Total policies: {len(policies_to_migrate)} of {len(self.wg_config.policies)} (after classification)")
        print(f"  With issues: {policies_with_issues}")
        print(f"  With applications: {policies_with_apps}")
        print(f"  With service groups: {policies_with_service_groups}")
        if policies_with_users > 0:
            print(f"  With users: {policies_with_users}")
        
        statistics = {
            'total_wg_objects': len(self.address_objects),
            'mapped_to_existing': len(address_mappings),
            'needs_creation': len(objects_to_create),
            'unmapped': 0,
            'total_policies': len(policies_to_migrate),
            'policies_skipped': sum(1 for s in skipped_policies if not s.get('included')),
            'policies_with_issues': policies_with_issues,
            'policies_with_warnings': policies_with_warnings,
            'policies_with_errors': policies_with_issues,
            'policies_with_applications': policies_with_apps,
            'policies_with_service_groups': policies_with_service_groups,
            'policies_with_users': policies_with_users,
            'service_groups_to_create': len(service_groups_to_create)
        }
        
        return MigrationPlan(
            address_mappings=address_mappings,
            service_mappings=service_mappings,
            application_mappings=application_mappings,
            objects_to_create=objects_to_create,
            policies_to_create=policies_to_create,
            statistics=statistics,
            service_groups_to_create=service_groups_to_create,
            skipped_policies=skipped_policies
        )
    
    def _plan_policy(self, policy: WatchGuardPolicy, address_mappings: Dict,
                     service_mappings: Dict, application_mappings: Dict) -> Tuple[Dict, List]:
        """Plan policy with alias resolution, service group support, and user mapping."""
        issues = []
        warnings = []
        
        # Resolve sources
        source_objects = []
        for member in policy.source_members:
            resolved_names = self.resolve_alias_to_objects(member)
            for name in resolved_names:
                if name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    # Use correct type for the object
                    fmc_type = self._get_fmc_type_for_object(wg_obj)
                    source_objects.append({
                        'type': fmc_type,
                        'name': name
                    })
        
        # Resolve destinations
        dest_objects = []
        for member in policy.destination_members:
            resolved_names = self.resolve_alias_to_objects(member)
            for name in resolved_names:
                if name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    # Use correct type for the object
                    fmc_type = self._get_fmc_type_for_object(wg_obj)
                    dest_objects.append({
                        'type': fmc_type,
                        'name': name
                    })
        
        # =====================================================================
        # Resolve users from source aliases (v7)
        # =====================================================================
        user_objects = []
        unmapped_users = []
        users_resolved = []  # Track WatchGuard users for this policy
        
        if self.user_mapper:
            # Collect users from source aliases
            for member in policy.source_members:
                resolved_users = self.resolve_alias_to_users(member)
                users_resolved.extend(resolved_users)
            
            # Deduplicate
            users_resolved = list(set(users_resolved))
            
            # Map WatchGuard users to FMC realm users
            for wg_user in users_resolved:
                fmc_user_ref = self.user_mapper.get_fmc_user_ref(wg_user)
                if fmc_user_ref:
                    user_objects.append(fmc_user_ref)
                else:
                    unmapped_users.append(wg_user)
            
            # Log warnings for unmapped users
            for unmapped in unmapped_users:
                warnings.append(f"User '{unmapped}' has no FMC realm user mapping")
        
        # =====================================================================
        # Resolve services (updated for v5 with service groups)
        # =====================================================================
        service_objects = []          # TCP/UDP port objects or port groups
        icmp_objects = []             # ICMP objects (separate from port groups)
        protocol_objects = []         # Protocol-only (GRE, ESP) - use literal
        uses_service_group = False
        service_group_name = None
        
        if policy.service and policy.service != 'Any':
            resolved = self.resolve_service(policy.service)
            
            if resolved['type'] == 'group':
                # Service maps to a group
                group: WatchGuardServiceGroup = resolved['group']
                uses_service_group = True
                service_group_name = group.name
                
                # If group has 2+ TCP/UDP members, use the port group
                if group.needs_port_group:
                    # Reference the port group (will be created in executor)
                    service_objects.append({
                        'type': 'PortObjectGroup',
                        'name': group.name,
                        'needs_creation': True,
                        'is_service_group': True
                    })
                else:
                    # Single TCP/UDP member - reference it directly
                    for member_name in group.members:
                        svc = self.services_by_name.get(member_name)
                        if svc:
                            # Check if it's mapped to existing FMC object
                            if member_name in service_mappings:
                                obj = service_mappings[member_name]
                                service_objects.append({
                                    'type': obj.type,
                                    'id': obj.id,
                                    'name': obj.name
                                })
                            else:
                                service_objects.append({
                                    'type': 'ProtocolPortObject',
                                    'name': member_name,
                                    'protocol': svc.protocol,
                                    'port': svc.port,
                                    'needs_creation': True
                                })
                
                # Handle ICMP members (must be added separately)
                for icmp_name in group.icmp_members:
                    svc = self.services_by_name.get(icmp_name)
                    if svc:
                        icmp_version = getattr(svc, 'icmp_version', 'v4')
                        icmp_type = 'ICMPV6Object' if icmp_version == 'v6' else 'ICMPV4Object'
                        icmp_objects.append({
                            'type': icmp_type,
                            'name': icmp_name,
                            'needs_creation': True
                        })
                
                # Handle protocol-only members (GRE, ESP, etc.)
                for proto_name in group.protocol_members:
                    svc = self.services_by_name.get(proto_name)
                    if svc:
                        protocol_num = getattr(svc, 'protocol_number', None)
                        protocol_objects.append({
                            'type': 'ProtocolLiteral',
                            'name': proto_name,
                            'protocol': svc.protocol,
                            'protocol_number': protocol_num
                        })
                
                # Log group warnings
                if group.warnings:
                    for w in group.warnings:
                        warnings.append(f"Service group '{group.original_name}': {w}")
                
                # Informational notes
                if group.icmp_members:
                    warnings.append(f"Service '{policy.service}' includes ICMP ({len(group.icmp_members)} objects) - added separately")
                if group.protocol_members:
                    warnings.append(f"Service '{policy.service}' includes protocol-only ({len(group.protocol_members)} objects) - require special handling")
            
            elif resolved['type'] == 'service':
                # Single service (not in a group)
                svc: WatchGuardService = resolved['service']
                
                if svc.is_port_based:
                    # TCP/UDP service
                    if policy.service in service_mappings:
                        obj = service_mappings[policy.service]
                        service_objects.append({
                            'type': obj.type,
                            'id': obj.id,
                            'name': obj.name
                        })
                    elif svc.name in service_mappings:
                        obj = service_mappings[svc.name]
                        service_objects.append({
                            'type': obj.type,
                            'id': obj.id,
                            'name': obj.name
                        })
                    else:
                        warnings.append(f"Service '{policy.service}' needs to be created")
                        service_objects.append({
                            'type': 'ProtocolPortObject',
                            'name': svc.name,
                            'protocol': svc.protocol,
                            'port': svc.port,
                            'needs_creation': True
                        })
                
                elif svc.is_icmp:
                    # ICMP service
                    icmp_version = getattr(svc, 'icmp_version', 'v4')
                    icmp_type = 'ICMPV6Object' if icmp_version == 'v6' else 'ICMPV4Object'
                    icmp_objects.append({
                        'type': icmp_type,
                        'name': svc.name,
                        'needs_creation': True
                    })
                
                elif svc.is_protocol_only:
                    # Protocol-only (GRE, ESP, etc.)
                    protocol_num = getattr(svc, 'protocol_number', None)
                    protocol_objects.append({
                        'type': 'ProtocolLiteral',
                        'name': svc.name,
                        'protocol': svc.protocol,
                        'protocol_number': protocol_num
                    })
                
                else:
                    # Other/unsupported
                    warnings.append(f"Service '{policy.service}' has unsupported protocol '{svc.protocol}'")
            
            elif resolved['type'] == 'not_found':
                # Try legacy lookup
                if policy.service in service_mappings:
                    obj = service_mappings[policy.service]
                    service_objects.append({
                        'type': obj.type,
                        'id': obj.id,
                        'name': obj.name
                    })
                elif policy.service in self.services:
                    wg_svc = self.services[policy.service]
                    warnings.append(f"Service '{policy.service}' needs to be created")
                    service_objects.append({
                        'type': 'ProtocolPortObject',
                        'name': policy.service,
                        'protocol': wg_svc.protocol,
                        'port': wg_svc.port,
                        'needs_creation': True
                    })
                else:
                    warnings.append(f"Service '{policy.service}' not found")
        
        # Applications - resolve from app_action reference
        application_objects = []
        unmapped_apps = []
        if policy.app_action:
            # Look up the app_action by name
            app_action = self._get_app_action_by_name(policy.app_action)
            if app_action:
                # Get allowed apps from the app_action and map them to FMC
                for wg_app_name in app_action.allowed_apps:
                    if wg_app_name in application_mappings:
                        fmc_app = application_mappings[wg_app_name]
                        application_objects.append({
                            'type': 'Application',
                            'id': fmc_app.id,
                            'name': fmc_app.name
                        })
                    else:
                        unmapped_apps.append(wg_app_name)
                
                # Log warnings for unmapped applications
                for unmapped in unmapped_apps:
                    warnings.append(f"Application '{unmapped}' has no FMC mapping (app_action: {policy.app_action})")
            else:
                warnings.append(f"App action '{policy.app_action}' not found in WatchGuard config")
        
        # Check issues
        if not source_objects and policy.source_members and policy.source_members != ['Any']:
            issues.append(f"No source objects resolved from: {policy.source_members}")
        if not dest_objects and policy.destination_members and policy.destination_members != ['Any']:
            issues.append(f"No destination objects resolved from: {policy.destination_members}")
        
        # Count network vs URL objects for accurate warnings
        source_network_count = len([o for o in source_objects if o.get('type') != 'Url'])
        dest_network_count = len([o for o in dest_objects if o.get('type') != 'Url'])
        source_url_count = len([o for o in source_objects if o.get('type') == 'Url'])
        dest_url_count = len([o for o in dest_objects if o.get('type') == 'Url'])
        
        # Warn if rule has too many network objects (FMC limit is 200 per field)
        if source_network_count > 200:
            warnings.append(f"Rule has {source_network_count} source network objects (FMC limit is 200, will auto-create group)")
        if dest_network_count > 200:
            warnings.append(f"Rule has {dest_network_count} destination network objects (FMC limit is 200, will auto-create group)")
        
        # Note URL objects
        if source_url_count > 0:
            warnings.append(f"Rule has {source_url_count} source URL objects (FMC doesn't support source URLs)")
        
        # Build FMC rule
        action = self._map_action(policy.action)
        
        # FMC does not support logEnd for BLOCK actions
        if action == 'BLOCK':
            log_begin = policy.log_enabled
            log_end = False
        else:
            log_begin = False
            log_end = policy.log_enabled
        
        fmc_rule = {
            'name': policy.name[:50],
            'action': action,
            'enabled': policy.enabled,
            'sendEventsToFMC': policy.log_enabled,
            'logBegin': log_begin,
            'logEnd': log_end
        }
        
        if source_objects:
            fmc_rule['sourceNetworks'] = {'objects': source_objects}
        if dest_objects:
            fmc_rule['destinationNetworks'] = {'objects': dest_objects}
        
        # Add users if any were resolved (v7)
        if user_objects:
            fmc_rule['users'] = {'objects': user_objects}
        
        # Add port objects (TCP/UDP and port groups)
        if service_objects:
            valid_services = [s for s in service_objects if 'id' in s and not s.get('needs_creation')]
            needs_creation = [s for s in service_objects if s.get('needs_creation')]
            
            if valid_services or needs_creation:
                fmc_rule['destinationPorts'] = {'objects': valid_services + needs_creation}
        
        # Add ICMP objects (separate from port objects)
        if icmp_objects:
            # ICMP goes in destinationPorts but as separate objects
            if 'destinationPorts' not in fmc_rule:
                fmc_rule['destinationPorts'] = {'objects': []}
            fmc_rule['destinationPorts']['objects'].extend(icmp_objects)
        
        # Add protocol-only objects (GRE, ESP, etc.)
        if protocol_objects:
            # These need to be handled as literals in the rule
            if 'destinationPorts' not in fmc_rule:
                fmc_rule['destinationPorts'] = {'objects': [], 'literals': []}
            if 'literals' not in fmc_rule['destinationPorts']:
                fmc_rule['destinationPorts']['literals'] = []
            
            for proto in protocol_objects:
                fmc_rule['destinationPorts']['literals'].append({
                    'type': 'ProtocolPortObject',
                    'protocol': proto['protocol_number'] or proto['protocol']
                })
        
        # Add applications if any were resolved
        if application_objects:
            fmc_rule['applications'] = {'applications': application_objects}
        
        return {
            'wg_policy': policy.name,
            'fmc_rule': fmc_rule,
            'issues': issues,
            'warnings': warnings,
            'errors': issues,
            'source_members_original': policy.source_members,
            'dest_members_original': policy.destination_members,
            'service_original': policy.service,
            'app_action_original': policy.app_action,
            'applications_mapped': len(application_objects),
            'applications_unmapped': unmapped_apps,
            'uses_service_group': uses_service_group,
            'service_group_name': service_group_name,
            'icmp_objects': icmp_objects,
            'protocol_objects': protocol_objects,
            # v7: user tracking
            'users_resolved': users_resolved,
            'users_mapped': len(user_objects),
            'users_unmapped': unmapped_users
        }, issues
    
    def _map_action(self, wg_action: str) -> str:
        """Map WatchGuard action to FMC action."""
        action_map = {
            'allow': 'ALLOW',
            'deny': 'BLOCK',
            'drop': 'BLOCK',
            'proxy': 'ALLOW',
            'block': 'BLOCK'
        }
        return action_map.get(wg_action.lower(), 'ALLOW')
    
    def _get_fmc_type_for_object(self, wg_obj: WatchGuardAddress) -> str:
        """Get the correct FMC type for a WatchGuard object, accounting for special cases."""
        # If it's a wildcard FQDN, it will be created as a URL object
        if wg_obj.name in self.wildcard_fqdns:
            return 'Url'
        
        # If it's a /32 network, it will be created as a Host object
        if wg_obj.name in self.host_networks:
            return 'Host'
        
        # Otherwise use standard mapping
        return self._get_fmc_type(wg_obj.object_type)
    
    def _get_fmc_type(self, wg_type: str) -> str:
        """Convert WatchGuard type to FMC type."""
        return {'host': 'Host', 'network': 'Network', 'range': 'Range', 'fqdn': 'FQDN'}.get(wg_type, 'Host')
