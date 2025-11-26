"""
Migration Planner - Creates migration plan with proper alias resolution.
"""

from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, asdict
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


class MigrationPlanner:
    """Plans migration from WatchGuard to FMC with proper alias resolution."""
    
    def __init__(self, wg_config: WatchGuardConfig, fmc_discovery, 
                 service_mapper, app_mapper):
        self.wg_config = wg_config
        self.fmc_discovery = fmc_discovery
        self.service_mapper = service_mapper
        self.app_mapper = app_mapper
        self._build_lookups()
    
    def _build_lookups(self):
        """Build lookup structures."""
        self.address_objects = {}
        for host in self.wg_config.hosts:
            self.address_objects[host.name] = host
        for network in self.wg_config.networks:
            self.address_objects[network.name] = network
        for range_obj in self.wg_config.ranges:
            self.address_objects[range_obj.name] = range_obj
        for fqdn in self.wg_config.fqdns:
            self.address_objects[fqdn.name] = fqdn
        
        self.address_groups = {g.name: g for g in self.wg_config.address_groups}
        
        self.services = {}
        for tcp in self.wg_config.tcp_services:
            self.services[tcp.name] = tcp
        for udp in self.wg_config.udp_services:
            self.services[udp.name] = udp
        
        # Extract wildcard URLs from FQDNs for URL object creation
        self.url_objects = []
        for fqdn in self.wg_config.fqdns:
            if '*' in fqdn.fqdn or fqdn.fqdn.startswith('.'):
                # This is a wildcard that should be a URL object
                self.url_objects.append({
                    'name': fqdn.name,
                    'url': fqdn.fqdn,
                    'description': fqdn.description
                })
    
    def resolve_alias_to_objects(self, alias_name: str, visited: Optional[Set[str]] = None) -> List[str]:
        """Recursively resolve alias to address object names."""
        if visited is None:
            visited = set()
        
        if alias_name in visited:
            return []
        visited.add(alias_name)
        
        # Skip interface aliases
        if alias_name in ["Any", "Any-External", "Any-Trusted", "Any-Optional"]:
            return []
        
        # Direct address object
        if alias_name in self.address_objects:
            return [alias_name]
        
        # Not a group
        if alias_name not in self.address_groups:
            return []
        
        group = self.address_groups[alias_name]
        resolved = []
        
        # Direct members
        for member in group.members:
            if member in self.address_objects:
                resolved.append(member)
        
        # Recursive alias references
        for alias_ref in group.alias_references:
            resolved.extend(self.resolve_alias_to_objects(alias_ref, visited))
        
        return list(set(resolved))
    
    def build_plan(self) -> MigrationPlan:
        """Build migration plan."""
        print("\n" + "="*60)
        print("BUILDING MIGRATION PLAN")
        print("="*60)
        
        address_mappings = {}
        
        # Service mappings - handle different attribute names
        if hasattr(self.service_mapper, 'service_mappings'):
            service_mappings = self.service_mapper.service_mappings
        elif hasattr(self.service_mapper, 'mappings'):
            service_mappings = self.service_mapper.mappings
        else:
            service_mappings = {}
            print("  ⚠ Warning: ServiceMapper has no mappings attribute")
        
        # Application mappings - handle different attribute names
        if hasattr(self.app_mapper, 'mappings'):
            application_mappings = self.app_mapper.mappings
        elif hasattr(self.app_mapper, 'application_mappings'):
            application_mappings = self.app_mapper.application_mappings
        else:
            application_mappings = {}
            print("  ⚠ Warning: ApplicationMapper has no mappings attribute")
        
        objects_to_create = []
        policies_to_create = []
        
        print("\nMapping address objects...")
        for name, obj in self.address_objects.items():
            objects_to_create.append({'type': obj.object_type, 'wg_object': obj})
        
        print("\nMapping services...")
        for name, obj in self.services.items():
            if name not in service_mappings:
                objects_to_create.append({'type': 'service', 'wg_object': obj})
        
        print("\nMapping applications...")
        
        print("\nProcessing URL objects...")
        for url_obj in self.url_objects:
            objects_to_create.append({'type': 'url', 'wg_object': url_obj})
        print(f"  Found {len(self.url_objects)} wildcard URLs to create as URL objects")
        
        print("\nIdentifying objects to create...")
        print(f"  Objects to create: {len(objects_to_create)}")
        
        for group in self.wg_config.address_groups:
            objects_to_create.append({'type': 'address_group', 'wg_object': group})
        
        print("\nPlanning policy migration...")
        policies_with_issues = 0
        
        for policy in self.wg_config.policies:
            policy_plan, issues = self._plan_policy(policy, address_mappings, 
                                                    service_mappings, application_mappings)
            if issues:
                policies_with_issues += 1
            policies_to_create.append(policy_plan)
        
        print(f"  Total policies: {len(self.wg_config.policies)}")
        print(f"  With issues: {policies_with_issues}")
        
        statistics = {
            'total_wg_objects': len(self.address_objects),
            'mapped_to_existing': 0,
            'needs_creation': len(objects_to_create),
            'unmapped': 0,
            'total_policies': len(self.wg_config.policies),
            'policies_with_issues': policies_with_issues
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
        
        # WatchGuardPolicy only has source_members and destination_members
        # These can be either direct objects OR aliases - we resolve both
        
        # Resolve sources
        source_objects = []
        for member in policy.source_members:
            resolved_names = self.resolve_alias_to_objects(member)
            for name in resolved_names:
                if name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    source_objects.append({
                        'type': self._get_fmc_type(wg_obj.object_type),
                        'name': name
                    })
        
        # Resolve destinations
        dest_objects = []
        for member in policy.destination_members:
            resolved_names = self.resolve_alias_to_objects(member)
            for name in resolved_names:
                if name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    dest_objects.append({
                        'type': self._get_fmc_type(wg_obj.object_type),
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
                    'name': obj.name,
                    'protocol': getattr(obj, 'protocol', None),
                    'port': getattr(obj, 'port', None)
                })
            elif policy.service in self.services:
                wg_svc = self.services[policy.service]
                service_objects.append({
                    'type': 'ProtocolPortObject',
                    'name': policy.service,
                    'protocol': wg_svc.protocol,
                    'port': wg_svc.port
                })
            else:
                warnings.append(f"Service '{policy.service}' not found")
        
        # Check issues
        if not source_objects and policy.source_members and policy.source_members != ['Any']:
            issues.append(f"No source objects resolved from: {policy.source_members}")
        if not dest_objects and policy.destination_members and policy.destination_members != ['Any']:
            issues.append(f"No destination objects resolved from: {policy.destination_members}")
        
        # Build FMC rule
        fmc_rule = {
            'name': policy.name[:50],
            'action': policy.action.upper(),
            'enabled': policy.enabled,
            'sendEventsToFMC': policy.log_enabled,
            'logBegin': False,
            'logEnd': policy.log_enabled
        }
        
        if source_objects:
            fmc_rule['sourceNetworks'] = {'objects': source_objects}
        if dest_objects:
            fmc_rule['destinationNetworks'] = {'objects': dest_objects}
        if service_objects:
            fmc_rule['destinationPorts'] = {'objects': service_objects}
        
        return {
            'wg_policy': policy.name,
            'fmc_rule': fmc_rule,
            'issues': issues,
            'warnings': warnings,
            'errors': issues
        }, issues
    
    def _get_fmc_type(self, wg_type: str) -> str:
        """Convert WatchGuard type to FMC type."""
        return {'host': 'Host', 'network': 'Network', 'range': 'Range', 'fqdn': 'FQDN'}.get(wg_type, 'Host')
