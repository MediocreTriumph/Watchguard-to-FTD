"""
Migration Planner - Creates migration plan with proper alias resolution.
"""

from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
import json
from models import (
    WatchGuardConfig, WatchGuardPolicy, WatchGuardAddress, 
    WatchGuardAddressGroup, WatchGuardService, FMCObject
)


@dataclass  
class MigrationPlan:
    """Complete migration plan."""
    address_mappings: Dict[str, FMCObject]
    service_mappings: Dict[str, FMCObject]
    application_mappings: Dict[str, FMCObject]
    objects_to_create: List[Dict]
    policies_to_create: List[Dict]
    statistics: Dict[str, int]
    
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
                 service_mapper, app_mapper):
        self.wg_config = wg_config
        self.fmc_discovery = fmc_discovery
        self.service_mapper = service_mapper
        self.app_mapper = app_mapper
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
        
        self.services = {}
        for tcp in self.wg_config.tcp_services:
            self.services[tcp.name] = tcp
        for udp in self.wg_config.udp_services:
            self.services[udp.name] = udp
        
        # URL objects list for creation
        self.url_objects = []
        for fqdn in self.wg_config.fqdns:
            if self._is_wildcard_fqdn(fqdn):
                self.url_objects.append({
                    'name': fqdn.name,
                    'url': fqdn.fqdn,
                    'description': fqdn.description
                })
        
        print(f"  Identified {len(self.wildcard_fqdns)} wildcard FQDNs (will be URL objects)")
        print(f"  Identified {len(self.host_networks)} /32 networks (will be Host objects)")
    
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
        
        print("\nMapping address objects...")
        for name, obj in self.address_objects.items():
            # Use actual type (accounting for /32 hosts and wildcard URLs)
            actual_type = self._get_actual_type(obj)
            objects_to_create.append({'type': actual_type, 'wg_object': obj})
        
        print("\nMapping services...")
        for name, obj in self.services.items():
            if name not in service_mappings:
                objects_to_create.append({'type': 'service', 'wg_object': obj})
        
        print("\nProcessing URL objects...")
        # Note: wildcard FQDNs are already added with type='url' in the loop above
        # The url_objects list is now redundant but kept for backwards compatibility
        print(f"  Found {len(self.url_objects)} wildcard URLs to create as URL objects")
        
        print("\nIdentifying objects to create...")
        print(f"  Objects to create: {len(objects_to_create)}")
        
        for group in self.wg_config.address_groups:
            objects_to_create.append({'type': 'address_group', 'wg_object': group})
        
        print("\nPlanning policy migration...")
        policies_with_issues = 0
        policies_with_warnings = 0
        
        for policy in self.wg_config.policies:
            policy_plan, issues = self._plan_policy(policy, address_mappings, 
                                                    service_mappings, application_mappings)
            if issues:
                policies_with_issues += 1
            if policy_plan.get('warnings'):
                policies_with_warnings += 1
            policies_to_create.append(policy_plan)
        
        print(f"  Total policies: {len(self.wg_config.policies)}")
        print(f"  With issues: {policies_with_issues}")
        
        statistics = {
            'total_wg_objects': len(self.address_objects),
            'mapped_to_existing': len(address_mappings),
            'needs_creation': len(objects_to_create),
            'unmapped': 0,
            'total_policies': len(self.wg_config.policies),
            'policies_with_issues': policies_with_issues,
            'policies_with_warnings': policies_with_warnings,
            'policies_with_errors': policies_with_issues
        }
        
        return MigrationPlan(
            address_mappings=address_mappings,
            service_mappings=service_mappings,
            application_mappings=application_mappings,
            objects_to_create=objects_to_create,
            policies_to_create=policies_to_create,
            statistics=statistics
        )
    
    def _plan_policy(self, policy: WatchGuardPolicy, address_mappings: Dict,
                     service_mappings: Dict, application_mappings: Dict) -> tuple:
        """Plan policy with alias resolution."""
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
        
        # Services
        service_objects = []
        if policy.service and policy.service != 'Any':
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
        if dest_url_count > 0:
            # This is informational, not a warning - URLs are supported in destinations
            pass
        
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
        if service_objects:
            valid_services = [s for s in service_objects if 'id' in s and not s.get('needs_creation')]
            if valid_services:
                fmc_rule['destinationPorts'] = {'objects': valid_services}
        
        return {
            'wg_policy': policy.name,
            'fmc_rule': fmc_rule,
            'issues': issues,
            'warnings': warnings,
            'errors': issues,
            'source_members_original': policy.source_members,
            'dest_members_original': policy.destination_members,
            'service_original': policy.service
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
