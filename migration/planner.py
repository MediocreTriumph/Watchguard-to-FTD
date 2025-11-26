"""
Migration Planner - Creates migration plan with proper alias resolution.

This module:
1. Maps WatchGuard objects to FMC objects
2. Resolves aliases recursively to actual network objects
3. Creates FMC rules with proper source/destination objects
4. Handles service groups and deduplication
"""

from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, asdict
import json
from models import (
    WatchGuardConfig, WatchGuardPolicy, WatchGuardAddress, 
    WatchGuardAddressGroup, WatchGuardService, FMCObject
)
from fmc.discovery import FMCObjectDiscovery
from analysis.service_mapper import ServiceMapper
from analysis.app_mapper import ApplicationMapper


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
    """Plans migration from WatchGuard to FMC."""
    
    def __init__(self, wg_config: WatchGuardConfig, fmc_discovery: FMCObjectDiscovery,
                 service_mapper: ServiceMapper, app_mapper: ApplicationMapper):
        self.wg_config = wg_config
        self.fmc_discovery = fmc_discovery
        self.service_mapper = service_mapper
        self.app_mapper = app_mapper
        
        # Build lookup structures
        self._build_lookups()
    
    def _build_lookups(self):
        """Build lookup structures for quick access."""
        # Address objects by name
        self.address_objects = {}
        for host in self.wg_config.hosts:
            self.address_objects[host.name] = host
        for network in self.wg_config.networks:
            self.address_objects[network.name] = network
        for range_obj in self.wg_config.ranges:
            self.address_objects[range_obj.name] = range_obj
        for fqdn in self.wg_config.fqdns:
            self.address_objects[fqdn.name] = fqdn
        
        # Address groups by name
        self.address_groups = {group.name: group for group in self.wg_config.address_groups}
        
        # Services by name
        self.services = {}
        for tcp_svc in self.wg_config.tcp_services:
            self.services[tcp_svc.name] = tcp_svc
        for udp_svc in self.wg_config.udp_services:
            self.services[udp_svc.name] = udp_svc
    
    def resolve_alias_to_objects(self, alias_name: str, visited: Optional[Set[str]] = None) -> List[str]:
        """
        Recursively resolve an alias to actual address object names.
        
        Args:
            alias_name: Name of alias to resolve
            visited: Set of already visited aliases (prevents circular references)
            
        Returns:
            List of address object names
        """
        if visited is None:
            visited = set()
        
        # Prevent circular references
        if alias_name in visited:
            return []
        visited.add(alias_name)
        
        # Special cases
        if alias_name in ["Any", "Any-External", "Any-Trusted", "Any-Optional"]:
            return []  # These are interface aliases, not address objects
        
        # Check if it's an address group
        if alias_name not in self.address_groups:
            # It might be a direct address object
            if alias_name in self.address_objects:
                return [alias_name]
            return []
        
        group = self.address_groups[alias_name]
        resolved = []
        
        # Resolve direct members
        for member in group.members:
            if member in self.address_objects:
                resolved.append(member)
        
        # Resolve alias references recursively
        for alias_ref in group.alias_references:
            resolved.extend(self.resolve_alias_to_objects(alias_ref, visited))
        
        return list(set(resolved))  # Remove duplicates
    
    def build_plan(self) -> MigrationPlan:
        """Build complete migration plan."""
        print("\n" + "="*60)
        print("BUILDING MIGRATION PLAN")
        print("="*60)
        
        # Initialize mappings
        address_mappings = {}
        service_mappings = {}
        application_mappings = {}
        objects_to_create = []
        policies_to_create = []
        
        # Map addresses
        print("\nMapping address objects...")
        mapped_count = 0
        for name, obj in self.address_objects.items():
            # Check if exists in FMC
            fmc_obj = self._find_fmc_address_object(obj)
            if fmc_obj:
                address_mappings[name] = fmc_obj
                mapped_count += 1
            else:
                # Need to create
                objects_to_create.append({
                    'type': obj.object_type,
                    'wg_object': obj
                })
        
        print(f"  Mapped to existing: {mapped_count}")
        
        # Map services
        print("\nMapping services...")
        for name, obj in self.services.items():
            canonical = self.service_mapper.service_mappings.get(name)
            if canonical:
                service_mappings[name] = canonical
            else:
                # Need to create
                objects_to_create.append({
                    'type': 'service',
                    'wg_object': obj
                })
        
        # Map applications
        print("\nMapping applications...")
        for app_name, fmc_app in self.app_mapper.application_mappings.items():
            application_mappings[app_name] = fmc_app
        
        # Identify objects to create
        print("\nIdentifying objects to create...")
        print(f"  Objects to create: {len(objects_to_create)}")
        
        # Build address groups
        for group in self.wg_config.address_groups:
            objects_to_create.append({
                'type': 'address_group',
                'wg_object': group
            })
        
        # Plan policy migration
        print("\nPlanning policy migration...")
        total_policies = len(self.wg_config.policies)
        policies_with_issues = 0
        
        for policy in self.wg_config.policies:
            policy_plan, issues = self._plan_policy(policy, address_mappings, service_mappings, application_mappings)
            
            if issues:
                policies_with_issues += 1
            
            policies_to_create.append(policy_plan)
        
        print(f"  Total policies: {total_policies}")
        print(f"  With issues: {policies_with_issues}")
        
        # Build statistics
        statistics = {
            'total_wg_objects': len(self.address_objects),
            'mapped_to_existing': mapped_count,
            'needs_creation': len(objects_to_create),
            'unmapped': len(self.address_objects) - mapped_count - len([o for o in objects_to_create if o['type'] != 'address_group']),
            'total_policies': total_policies,
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
    
    def _find_fmc_address_object(self, wg_obj: WatchGuardAddress) -> Optional[FMCObject]:
        """Find matching FMC object for a WatchGuard address."""
        # Simple name matching for now
        # Could be enhanced with value matching
        return None  # Force creation for now
    
    def _plan_policy(self, policy: WatchGuardPolicy, address_mappings: Dict, 
                     service_mappings: Dict, application_mappings: Dict) -> tuple:
        """
        Plan migration for a single policy with proper alias resolution.
        
        Returns:
            Tuple of (policy_plan, issues_list)
        """
        issues = []
        warnings = []
        
        # Resolve source aliases to actual objects
        source_objects = []
        for alias in policy.source_aliases:
            resolved_names = self.resolve_alias_to_objects(alias)
            for name in resolved_names:
                if name in address_mappings:
                    obj = address_mappings[name]
                    source_objects.append({
                        'type': obj.type,
                        'id': obj.id,
                        'name': obj.name
                    })
                elif name in self.address_objects:
                    # Object will be created
                    wg_obj = self.address_objects[name]
                    source_objects.append({
                        'type': self._get_fmc_type(wg_obj.object_type),
                        'name': name,
                        'will_be_created': True
                    })
        
        # Add direct source members
        for member in policy.source_members:
            resolved_names = self.resolve_alias_to_objects(member)
            for name in resolved_names:
                if name in address_mappings:
                    obj = address_mappings[name]
                    source_objects.append({
                        'type': obj.type,
                        'id': obj.id,
                        'name': obj.name
                    })
                elif name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    source_objects.append({
                        'type': self._get_fmc_type(wg_obj.object_type),
                        'name': name,
                        'will_be_created': True
                    })
        
        # Resolve destination aliases
        dest_objects = []
        for alias in policy.destination_aliases:
            resolved_names = self.resolve_alias_to_objects(alias)
            for name in resolved_names:
                if name in address_mappings:
                    obj = address_mappings[name]
                    dest_objects.append({
                        'type': obj.type,
                        'id': obj.id,
                        'name': obj.name
                    })
                elif name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    dest_objects.append({
                        'type': self._get_fmc_type(wg_obj.object_type),
                        'name': name,
                        'will_be_created': True
                    })
        
        # Add direct destination members
        for member in policy.destination_members:
            resolved_names = self.resolve_alias_to_objects(member)
            for name in resolved_names:
                if name in address_mappings:
                    obj = address_mappings[name]
                    dest_objects.append({
                        'type': obj.type,
                        'id': obj.id,
                        'name': obj.name
                    })
                elif name in self.address_objects:
                    wg_obj = self.address_objects[name]
                    dest_objects.append({
                        'type': self._get_fmc_type(wg_obj.object_type),
                        'name': name,
                        'will_be_created': True
                    })
        
        # Resolve services
        service_objects = []
        if policy.service in service_mappings:
            obj = service_mappings[policy.service]
            service_objects.append({
                'type': obj.type,
                'id': obj.id,
                'name': obj.name,
                'protocol': obj.protocol,
                'port': obj.port
            })
        elif policy.service in self.services:
            wg_svc = self.services[policy.service]
            service_objects.append({
                'type': 'ProtocolPortObject',
                'name': policy.service,
                'protocol': wg_svc.protocol,
                'port': wg_svc.port,
                'will_be_created': True
            })
        else:
            issues.append(f"Service '{policy.service}' not found")
        
        # Check for issues
        if not source_objects and (policy.source_aliases or policy.source_members):
            issues.append("No source objects resolved")
        if not dest_objects and (policy.destination_aliases or policy.destination_members):
            issues.append("No destination objects resolved")
        
        # Build FMC rule
        fmc_rule = {
            'name': policy.name[:50],  # FMC 50 char limit
            'action': policy.action.upper(),
            'enabled': policy.enabled,
            'sendEventsToFMC': policy.log_enabled,
            'logBegin': False,
            'logEnd': policy.log_enabled
        }
        
        # Add source networks
        if source_objects:
            fmc_rule['sourceNetworks'] = {'objects': source_objects}
        
        # Add destination networks
        if dest_objects:
            fmc_rule['destinationNetworks'] = {'objects': dest_objects}
        
        # Add services
        if service_objects:
            fmc_rule['destinationPorts'] = {'objects': service_objects}
        
        return {
            'wg_policy': policy.name,
            'fmc_rule': fmc_rule,
            'issues': issues,
            'warnings': warnings,
            'errors': issues  # For compatibility
        }, issues
    
    def _get_fmc_type(self, wg_type: str) -> str:
        """Convert WatchGuard object type to FMC type."""
        type_map = {
            'host': 'Host',
            'network': 'Network',
            'range': 'Range',
            'fqdn': 'FQDN'
        }
        return type_map.get(wg_type, 'Host')
    
    def save_plan(self, plan: MigrationPlan, filename: str = "migration_plan.json"):
        """Save migration plan to JSON file."""
        # Convert to serializable format
        plan_dict = {
            'address_mappings': {k: asdict(v) for k, v in plan.address_mappings.items()},
            'service_mappings': {k: asdict(v) for k, v in plan.service_mappings.items()},
            'application_mappings': {k: asdict(v) for k, v in plan.application_mappings.items()},
            'objects_to_create': plan.objects_to_create,
            'policies_to_create': plan.policies_to_create,
            'statistics': plan.statistics
        }
        
        with open(filename, 'w') as f:
            json.dump(plan_dict, f, indent=2, default=str)
        
        print(f"\n✓ Migration plan saved to: {filename}")
