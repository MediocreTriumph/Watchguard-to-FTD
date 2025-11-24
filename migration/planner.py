"""
Migration planner - builds complete migration plan.
"""

from typing import Dict, List, Any
from models import (
    WatchGuardConfig, FMCObjects, FMCObject, MigrationPlan,
    WatchGuardPolicy, WatchGuardAddress, WatchGuardService
)
from analysis.service_mapper import ServiceMapper
from analysis.app_mapper import ApplicationMapper


class MigrationPlanner:
    """Builds complete migration plan mapping all WG objects to FMC."""
    
    def __init__(
        self,
        wg_config: WatchGuardConfig,
        fmc_objects: FMCObjects,
        service_mapper: ServiceMapper,
        app_mapper: ApplicationMapper
    ):
        self.wg_config = wg_config
        self.fmc_objects = fmc_objects
        self.service_mapper = service_mapper
        self.app_mapper = app_mapper
    
    def build_plan(self) -> MigrationPlan:
        """Build complete migration plan."""
        print("\n" + "="*60)
        print("BUILDING MIGRATION PLAN")
        print("="*60)
        
        plan = MigrationPlan()
        
        # Map address objects
        print("\nMapping address objects...")
        self._map_addresses(plan)
        
        # Map services (already done by service_mapper)
        print("\nMapping services...")
        plan.service_mappings = self.service_mapper.service_mappings.copy()
        
        # Map applications (already done by app_mapper)
        print("\nMapping applications...")
        plan.app_mappings = self.app_mapper.app_mappings.copy()
        
        # Identify objects that need creation
        print("\nIdentifying objects to create...")
        self._identify_objects_to_create(plan)
        
        # Build policy migration plan
        print("\nPlanning policy migration...")
        self._plan_policies(plan)
        
        # Calculate statistics
        self._calculate_statistics(plan)
        
        # Print summary
        self._print_summary(plan)
        
        return plan
    
    def _map_addresses(self, plan: MigrationPlan):
        """Map address objects to existing FMC objects or mark for creation."""
        # For now, we'll assume all addresses need to be created
        # In a more sophisticated version, we could try to match by IP/network value
        
        all_addresses = (
            self.wg_config.hosts +
            self.wg_config.networks +
            self.wg_config.ranges +
            [fqdn for fqdn in self.wg_config.fqdns if not fqdn.is_wildcard_fqdn]
        )
        
        for addr in all_addresses:
            # Check if exists in FMC by name
            existing = self.fmc_objects.get_by_name(addr.name, addr.object_type)
            
            if existing:
                plan.address_mappings[addr.name] = existing
            else:
                # Will need to create
                pass
        
        print(f"  Mapped to existing: {len(plan.address_mappings)}")
    
    def _identify_objects_to_create(self, plan: MigrationPlan):
        """Identify which objects need to be created."""
        # Addresses that need creation
        all_addresses = (
            self.wg_config.hosts +
            self.wg_config.networks +
            self.wg_config.ranges +
            [fqdn for fqdn in self.wg_config.fqdns if not fqdn.is_wildcard_fqdn]
        )
        
        for addr in all_addresses:
            if addr.name not in plan.address_mappings:
                plan.objects_to_create.append({
                    'type': addr.object_type,
                    'wg_object': addr
                })
        
        # Services that need creation (unmapped ones)
        for service_name, wg_service in self.service_mapper.unmapped_services.items():
            plan.objects_to_create.append({
                'type': 'service',
                'wg_object': wg_service
            })
        
        # Address groups (always create - FMC doesn't let us easily match these)
        for group in self.wg_config.address_groups:
            if not group.is_interface_alias:
                plan.objects_to_create.append({
                    'type': 'address_group',
                    'wg_object': group
                })
        
        print(f"  Objects to create: {len(plan.objects_to_create)}")
    
    def _plan_policies(self, plan: MigrationPlan):
        """Plan policy migration with resolved object references."""
        policies_with_issues = 0
        
        for wg_policy in self.wg_config.policies:
            policy_data = self._build_policy_data(wg_policy, plan)
            
            if 'errors' in policy_data and policy_data['errors']:
                policies_with_issues += 1
            
            plan.policies_to_create.append(policy_data)
        
        print(f"  Total policies: {len(plan.policies_to_create)}")
        print(f"  With issues: {policies_with_issues}")
    
    def _build_policy_data(self, wg_policy: WatchGuardPolicy, plan: MigrationPlan) -> Dict[str, Any]:
        """Build FMC policy data from WatchGuard policy."""
        policy_data = {
            'wg_policy': wg_policy,
            'fmc_rule': {},
            'warnings': [],
            'errors': []
        }
        
        # Basic policy info
        policy_data['fmc_rule']['name'] = wg_policy.name[:50]  # FMC limit
        policy_data['fmc_rule']['type'] = 'AccessRule'
        policy_data['fmc_rule']['enabled'] = wg_policy.enabled
        
        # Action
        action_map = {
            'Allow': 'ALLOW',
            'Deny': 'BLOCK',
            'Drop': 'BLOCK',
            'Proxy': 'ALLOW'  # Proxy policies become Allow with note
        }
        policy_data['fmc_rule']['action'] = action_map.get(wg_policy.action, 'BLOCK')
        
        # Logging
        policy_data['fmc_rule']['sendEventsToFMC'] = wg_policy.log_enabled
        policy_data['fmc_rule']['logBegin'] = False
        policy_data['fmc_rule']['logEnd'] = wg_policy.log_enabled
        
        # Description
        desc_parts = []
        if wg_policy.description:
            desc_parts.append(wg_policy.description)
        if wg_policy.has_nat:
            desc_parts.append(f"NAT Policy: {wg_policy.nat_policy}")
            policy_data['warnings'].append(f"Policy has NAT - not migrated: {wg_policy.nat_policy}")
        if wg_policy.action == 'Proxy':
            desc_parts.append("Original action: Proxy")
            policy_data['warnings'].append("Proxy action converted to Allow")
        
        policy_data['fmc_rule']['commentHistoryList'] = [' | '.join(desc_parts)[:1000]]
        
        # Service mapping - THIS IS THE CRITICAL PART
        service_obj = self.service_mapper.get_mapping(wg_policy.service)
        if service_obj:
            policy_data['fmc_rule']['destinationPorts'] = {
                'objects': [{
                    'type': service_obj.type,
                    'id': service_obj.id,
                    'name': service_obj.name
                }]
            }
        elif wg_policy.service != "Any":
            policy_data['errors'].append(f"Service not mapped: {wg_policy.service}")
        
        # Application control
        if wg_policy.has_app_control:
            app_objects = self._resolve_app_action(wg_policy.app_action, plan, policy_data)
            if app_objects:
                policy_data['fmc_rule']['applications'] = {
                    'applications': app_objects
                }
        
        return policy_data
    
    def _resolve_app_action(
        self,
        app_action_name: str,
        plan: MigrationPlan,
        policy_data: Dict
    ) -> List[Dict]:
        """Resolve application action to FMC application objects."""
        # Find the app action
        app_action = None
        for action in self.wg_config.app_actions:
            if action.name == app_action_name:
                app_action = action
                break
        
        if not app_action:
            policy_data['errors'].append(f"App action not found: {app_action_name}")
            return []
        
        # Map allowed apps
        app_objects = []
        unmapped_count = 0
        
        for wg_app_name in app_action.allowed_apps:
            fmc_app = self.app_mapper.get_mapping(wg_app_name)
            if fmc_app:
                app_objects.append({
                    'type': 'Application',
                    'id': fmc_app.id,
                    'name': fmc_app.name
                })
            else:
                unmapped_count += 1
        
        if unmapped_count > 0:
            policy_data['warnings'].append(
                f"{unmapped_count} applications not mapped in app action {app_action_name}"
            )
        
        # Note: Blocked apps would need separate deny rules or inverse logic
        if app_action.blocked_apps:
            policy_data['warnings'].append(
                f"App action has {len(app_action.blocked_apps)} blocked apps - not migrated"
            )
        
        return app_objects
    
    def _calculate_statistics(self, plan: MigrationPlan):
        """Calculate migration statistics."""
        plan.total_wg_objects = (
            len(self.wg_config.hosts) +
            len(self.wg_config.networks) +
            len(self.wg_config.ranges) +
            len(self.wg_config.fqdns) +
            len(self.wg_config.tcp_services) +
            len(self.wg_config.udp_services) +
            len(self.wg_config.icmp_services)
        )
        
        plan.mapped_to_existing = (
            len(plan.address_mappings) +
            len(plan.service_mappings) +
            len(plan.app_mappings)
        )
        
        plan.needs_creation = len(plan.objects_to_create)
        
        plan.unmapped = (
            len(self.service_mapper.unmapped_services) +
            len(self.app_mapper.unmapped_apps)
        )
    
    def _print_summary(self, plan: MigrationPlan):
        """Print migration plan summary."""
        print("\n" + "="*60)
        print("MIGRATION PLAN COMPLETE")
        print("="*60)
        
        print(f"\nObject Mapping:")
        print(f"  Total WG objects:     {plan.total_wg_objects}")
        print(f"  Mapped to existing:   {plan.mapped_to_existing}")
        print(f"  Needs creation:       {plan.needs_creation}")
        print(f"  Unmapped:             {plan.unmapped}")
        
        print(f"\nService Mapping:")
        svc_stats = self.service_mapper.get_statistics()
        print(f"  WG services:          {svc_stats['total_wg_services']}")
        print(f"  Canonical objects:    {svc_stats['unique_canonical_objects']}")
        print(f"  Deduplicated:         {svc_stats['services_deduplicated']}")
        
        print(f"\nApplication Mapping:")
        app_stats = self.app_mapper.get_statistics()
        print(f"  WG applications:      {app_stats['total_wg_apps']}")
        print(f"  Mapped:               {app_stats['mapped']}")
        print(f"  Unmapped:             {app_stats['unmapped']}")
        
        print(f"\nPolicies:")
        print(f"  To create:            {len(plan.policies_to_create)}")
        
        policies_with_warnings = sum(1 for p in plan.policies_to_create if p['warnings'])
        policies_with_errors = sum(1 for p in plan.policies_to_create if p['errors'])
        
        print(f"  With warnings:        {policies_with_warnings}")
        print(f"  With errors:          {policies_with_errors}")
