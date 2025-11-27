"""
Migration executor - creates objects and policies in FMC.
Enhanced with better logging, duplicate detection, proper ID resolution,
and automatic network group creation for rules exceeding 200 objects.
"""

import time
import re
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from models import (
    WatchGuardAddress, WatchGuardService, 
    WatchGuardAddressGroup, FMCObject
)
from fmc.client import FMCClient


# FMC limit for objects per rule field
FMC_MAX_OBJECTS_PER_RULE = 200


class MigrationExecutor:
    """Executes migration plan by creating objects in FMC."""
    
    def __init__(self, fmc_client: FMCClient, plan, fmc_discovery=None):
        self.fmc = fmc_client
        self.plan = plan
        self.fmc_discovery = fmc_discovery
        self.created_objects: Dict[str, FMCObject] = {}
        self.execution_log: List[str] = []
        self.errors: List[str] = []
        self.skipped_existing: List[str] = []
        self.name_map: Dict[str, str] = {}
        self.reverse_name_map: Dict[str, str] = {}
        self.used_names: Set[str] = set()
        self.auto_created_groups: int = 0  # Track groups created for 200+ rules
        
        # Master object lookup: name -> FMCObject
        self.all_objects: Dict[str, FMCObject] = {}
        self._build_object_lookup()
    
    def _build_object_lookup(self):
        """Build master object lookup from discovered FMC objects."""
        if self.fmc_discovery:
            for name, obj in self.fmc_discovery.hosts.items():
                self.all_objects[name] = obj
            for name, obj in self.fmc_discovery.networks.items():
                self.all_objects[name] = obj
            for name, obj in self.fmc_discovery.ranges.items():
                self.all_objects[name] = obj
            for name, obj in self.fmc_discovery.fqdns.items():
                self.all_objects[name] = obj
            for name, obj in self.fmc_discovery.network_groups.items():
                self.all_objects[name] = obj
            for name, obj in self.fmc_discovery.port_objects.items():
                self.all_objects[name] = obj
            if hasattr(self.fmc_discovery, 'url_objects'):
                for name, obj in self.fmc_discovery.url_objects.items():
                    self.all_objects[name] = obj
        
        if hasattr(self.plan, 'service_mappings'):
            for name, obj in self.plan.service_mappings.items():
                self.all_objects[name] = obj
        
        print(f"\n  Object lookup initialized with {len(self.all_objects)} objects")
    
    def _sanitize_name(self, name: str, track: bool = True) -> str:
        """Sanitize object name to be FMC-compliant."""
        if name in self.name_map:
            return self.name_map[name]
        
        sanitized = name
        invalid_chars = r'[:?*<>|/\\\s]'
        sanitized = re.sub(invalid_chars, '_', sanitized)
        sanitized = sanitized.strip('_')
        sanitized = re.sub(r'_+', '_', sanitized)
        
        if len(sanitized) > 50:
            sanitized = sanitized[:50].rstrip('_')
        
        if not sanitized:
            sanitized = "unnamed_object"
        
        original_sanitized = sanitized
        counter = 1
        while sanitized in self.used_names:
            suffix = f"_{counter}"
            max_base_len = 50 - len(suffix)
            sanitized = original_sanitized[:max_base_len] + suffix
            counter += 1
        
        if track:
            self.name_map[name] = sanitized
            self.reverse_name_map[sanitized] = name
            self.used_names.add(sanitized)
        
        return sanitized
    
    def _is_already_exists_error(self, error_text: str) -> bool:
        """Check if error is 'already exists' type."""
        if not error_text:
            return False
        return "already exists" in error_text.lower()
    
    def _lookup_object(self, name: str) -> Optional[FMCObject]:
        """Look up an object by name using multiple strategies."""
        if name in self.all_objects:
            return self.all_objects[name]
        
        if name in self.created_objects:
            return self.created_objects[name]
        
        sanitized = self._sanitize_name(name, track=False)
        if sanitized in self.all_objects:
            return self.all_objects[sanitized]
        
        if name in self.name_map:
            mapped_name = self.name_map[name]
            if mapped_name in self.all_objects:
                return self.all_objects[mapped_name]
        
        if name in self.reverse_name_map:
            original = self.reverse_name_map[name]
            if original in self.all_objects:
                return self.all_objects[original]
            if original in self.created_objects:
                return self.created_objects[original]
        
        return None
    
    def _create_network_group_for_rule(self, rule_name: str, objects: List[Dict], 
                                        field_type: str) -> Optional[FMCObject]:
        """
        Create a network group on-the-fly for rules that exceed 200 objects.
        
        Args:
            rule_name: Name of the rule (for generating group name)
            objects: List of resolved object dicts with type/id/name
            field_type: 'src' or 'dst' to indicate source or destination
            
        Returns:
            FMCObject for the created group, or None if creation failed
        """
        # Generate a unique group name
        base_name = f"{rule_name}_{field_type}_grp"
        group_name = self._sanitize_name(base_name)
        
        # Check if we already created this group
        existing = self._lookup_object(group_name)
        if existing:
            return existing
        
        # Build the group data
        group_data = {
            'name': group_name,
            'type': 'NetworkGroup',
            'objects': objects,
            'description': f'Auto-created group for rule {rule_name} ({len(objects)} objects)'[:200]
        }
        
        print(f"  → Creating network group '{group_name}' for {len(objects)} objects...")
        
        result = self.fmc.create_object('networkgroups', group_data)
        
        if 'error' in result:
            error_text = result.get('error', 'Unknown error')
            if self._is_already_exists_error(error_text):
                # Try to fetch the existing group
                print(f"    Group '{group_name}' already exists, will use existing")
                # We don't have a way to fetch by name here, so return None
                # The rule creation will fail but with a clearer error
                return None
            else:
                print(f"    ✗ Failed to create group: {error_text}")
                return None
        
        # Success - store the created group
        fmc_obj = FMCObject(
            id=result['id'],
            name=result['name'],
            type='NetworkGroup'
        )
        self.created_objects[group_name] = fmc_obj
        self.all_objects[group_name] = fmc_obj
        self.auto_created_groups += 1
        
        print(f"    ✓ Created group '{group_name}' (ID: {result['id']})")
        
        return fmc_obj
    
    def execute(self, acp_name: str) -> bool:
        """Execute the migration plan."""
        print("\n" + "="*60)
        print("EXECUTING MIGRATION")
        print("="*60)
        
        success = True
        
        if not self._create_network_objects():
            success = False
        
        if not self._create_url_objects():
            success = False
        
        if not self._create_service_objects():
            success = False
        
        if not self._create_network_groups():
            success = False
        
        acp_id = self._create_access_policy(acp_name)
        if not acp_id:
            success = False
            return success
        
        if not self._create_access_rules(acp_id):
            success = False
        
        self._print_execution_summary()
        
        return success
    
    def _is_wildcard_fqdn(self, fqdn_value: str) -> bool:
        """Check if an FQDN contains wildcards."""
        if not fqdn_value:
            return False
        return '*' in fqdn_value or fqdn_value.startswith('.')
    
    def _create_network_objects(self) -> bool:
        """Create all network objects (hosts, networks, ranges, FQDNs)."""
        print("\n" + "-"*60)
        print("Creating Network Objects")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        wildcard_count = 0
        
        for obj_def in self.plan.objects_to_create:
            obj_type = obj_def['type']
            
            if obj_type not in ['host', 'network', 'range', 'fqdn']:
                continue
            
            wg_obj: WatchGuardAddress = obj_def['wg_object']
            
            if obj_type == 'fqdn' and hasattr(wg_obj, 'fqdn') and self._is_wildcard_fqdn(wg_obj.fqdn):
                wildcard_count += 1
                continue
            
            if self._lookup_object(wg_obj.name):
                self.skipped_existing.append(f"[{obj_type}] {wg_obj.name}")
                skipped_count += 1
                continue
            
            fmc_data = self._build_network_object_data(wg_obj)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for {wg_obj.name}")
                error_count += 1
                continue
            
            result = self.fmc.create_object(fmc_data['fmc_type'], fmc_data['data'])
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[{obj_type}] {wg_obj.name}")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create {wg_obj.name}: {error_text}")
                    error_count += 1
            else:
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type']
                )
                self.created_objects[wg_obj.name] = fmc_obj
                self.all_objects[wg_obj.name] = fmc_obj
                sanitized = self._sanitize_name(wg_obj.name)
                self.all_objects[sanitized] = fmc_obj
                created_count += 1
                
                if created_count % 50 == 0:
                    print(f"  Created {created_count} objects...")
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} network objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if wildcard_count > 0:
            print(f"ℹ Deferred {wildcard_count} wildcard FQDNs (will create as URL objects)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _create_url_objects(self) -> bool:
        """Create URL objects for wildcard FQDNs."""
        print("\n" + "-"*60)
        print("Creating URL Objects (for wildcard FQDNs)")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for obj_def in self.plan.objects_to_create:
            obj_type = obj_def['type']
            
            if obj_type == 'url':
                wg_obj = obj_def['wg_object']
                if isinstance(wg_obj, dict):
                    name = wg_obj.get('name', '')
                    url = wg_obj.get('url', '')
                    description = wg_obj.get('description', '')
                else:
                    continue
            elif obj_type == 'fqdn':
                wg_obj: WatchGuardAddress = obj_def['wg_object']
                if not (hasattr(wg_obj, 'fqdn') and self._is_wildcard_fqdn(wg_obj.fqdn)):
                    continue
                name = wg_obj.name
                url = wg_obj.fqdn
                description = wg_obj.description if wg_obj.description else ''
            else:
                continue
            
            if self._lookup_object(name):
                self.skipped_existing.append(f"[url] {name}")
                skipped_count += 1
                continue
            
            sanitized_name = self._sanitize_name(name)
            
            fmc_data = {
                'name': sanitized_name,
                'type': 'Url',
                'url': url,
                'description': description[:200] if description else ''
            }
            
            result = self.fmc.create_object('urls', fmc_data)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[url] {name}")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create URL {name}: {error_text}")
                    error_count += 1
            else:
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type='Url'
                )
                self.created_objects[name] = fmc_obj
                self.all_objects[name] = fmc_obj
                self.all_objects[sanitized_name] = fmc_obj
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} URL objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _build_network_object_data(self, wg_obj: WatchGuardAddress) -> Optional[Dict]:
        """Build FMC API data for a network object."""
        obj_type = wg_obj.object_type
        sanitized_name = self._sanitize_name(wg_obj.name)
        
        if obj_type == 'host':
            return {
                'fmc_type': 'hosts',
                'data': {
                    'name': sanitized_name,
                    'type': 'Host',
                    'value': wg_obj.ip,
                    'description': wg_obj.description[:200] if wg_obj.description else ''
                }
            }
        elif obj_type == 'network':
            return {
                'fmc_type': 'networks',
                'data': {
                    'name': sanitized_name,
                    'type': 'Network',
                    'value': f"{wg_obj.network}/{wg_obj.mask}",
                    'description': wg_obj.description[:200] if wg_obj.description else ''
                }
            }
        elif obj_type == 'range':
            return {
                'fmc_type': 'ranges',
                'data': {
                    'name': sanitized_name,
                    'type': 'Range',
                    'value': f"{wg_obj.start}-{wg_obj.end}",
                    'description': wg_obj.description[:200] if wg_obj.description else ''
                }
            }
        elif obj_type == 'fqdn':
            return {
                'fmc_type': 'fqdns',
                'data': {
                    'name': sanitized_name,
                    'type': 'FQDN',
                    'value': wg_obj.fqdn,
                    'dnsResolution': 'IPV4_ONLY',
                    'description': wg_obj.description[:200] if wg_obj.description else ''
                }
            }
        return None
    
    def _create_service_objects(self) -> bool:
        """Create service objects for unmapped services."""
        print("\n" + "-"*60)
        print("Creating Service Objects")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'service':
                continue
            
            wg_svc: WatchGuardService = obj_def['wg_object']
            
            if self._lookup_object(wg_svc.name):
                self.skipped_existing.append(f"[service] {wg_svc.name}")
                skipped_count += 1
                continue
            
            fmc_data = self._build_service_object_data(wg_svc)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for service {wg_svc.name}")
                error_count += 1
                continue
            
            result = self.fmc.create_object(fmc_data['fmc_type'], fmc_data['data'])
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[service] {wg_svc.name}")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create service {wg_svc.name}: {error_text}")
                    error_count += 1
            else:
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type'],
                    protocol=wg_svc.protocol,
                    port=wg_svc.port
                )
                self.created_objects[wg_svc.name] = fmc_obj
                self.all_objects[wg_svc.name] = fmc_obj
                sanitized = self._sanitize_name(wg_svc.name)
                self.all_objects[sanitized] = fmc_obj
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} service objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _build_service_object_data(self, wg_svc: WatchGuardService) -> Optional[Dict]:
        """Build FMC API data for a service object."""
        sanitized_name = self._sanitize_name(wg_svc.name)
        
        if wg_svc.protocol in ['TCP', 'UDP']:
            return {
                'fmc_type': 'protocolportobjects',
                'data': {
                    'name': sanitized_name,
                    'type': 'ProtocolPortObject',
                    'protocol': wg_svc.protocol,
                    'port': wg_svc.port,
                    'description': wg_svc.description[:200] if wg_svc.description else ''
                }
            }
        elif wg_svc.protocol == 'ICMP':
            return {
                'fmc_type': 'icmpv4objects',
                'data': {
                    'name': sanitized_name,
                    'type': 'ICMPV4Object',
                    'icmpType': 'ANY',
                    'description': wg_svc.description[:200] if wg_svc.description else ''
                }
            }
        return None
    
    def _create_network_groups(self) -> bool:
        """Create network groups from WatchGuard address groups."""
        print("\n" + "-"*60)
        print("Creating Network Groups")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'address_group':
                continue
            
            wg_group: WatchGuardAddressGroup = obj_def['wg_object']
            
            if self._lookup_object(wg_group.name):
                self.skipped_existing.append(f"[group] {wg_group.name}")
                skipped_count += 1
                continue
            
            fmc_data = self._build_network_group_data(wg_group)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for group {wg_group.name} (no valid members)")
                error_count += 1
                continue
            
            result = self.fmc.create_object('networkgroups', fmc_data)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[group] {wg_group.name}")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create group {wg_group.name}: {error_text}")
                    error_count += 1
            else:
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type']
                )
                self.created_objects[wg_group.name] = fmc_obj
                self.all_objects[wg_group.name] = fmc_obj
                sanitized = self._sanitize_name(wg_group.name)
                self.all_objects[sanitized] = fmc_obj
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} network groups")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _build_network_group_data(self, wg_group: WatchGuardAddressGroup) -> Optional[Dict]:
        """Build FMC API data for a network group."""
        sanitized_name = self._sanitize_name(wg_group.name)
        
        objects = []
        for member_name in wg_group.members:
            obj = self._lookup_object(member_name)
            if obj:
                objects.append({
                    'type': obj.type,
                    'id': obj.id,
                    'name': obj.name
                })
        
        if not objects:
            return None
        
        return {
            'name': sanitized_name,
            'type': 'NetworkGroup',
            'objects': objects,
            'description': wg_group.description[:200] if wg_group.description else ''
        }
    
    def _create_access_policy(self, acp_name: str) -> Optional[str]:
        """Create Access Control Policy."""
        print("\n" + "-"*60)
        print(f"Creating Access Control Policy: {acp_name}")
        print("-"*60)
        
        result = self.fmc.create_access_policy(acp_name, default_action="BLOCK")
        
        if 'error' in result:
            self.errors.append(f"Failed to create ACP: {result.get('error', 'Unknown error')}")
            print(f"✗ Failed to create ACP")
            return None
        
        acp_id = result['id']
        print(f"✓ Created ACP: {acp_name} (ID: {acp_id})")
        
        return acp_id
    
    def _resolve_rule_objects(self, fmc_rule: Dict, policy_data: Dict) -> Tuple[Dict, List[str]]:
        """
        Resolve object names to IDs in a rule before sending to FMC.
        If a field has >200 objects, automatically create a network group.
        """
        resolved_rule = dict(fmc_rule)
        resolution_issues = []
        rule_name = fmc_rule.get('name', 'unnamed_rule')
        
        # Resolve source networks
        if 'sourceNetworks' in resolved_rule:
            resolved_sources = []
            for obj_ref in resolved_rule['sourceNetworks'].get('objects', []):
                obj_name = obj_ref.get('name')
                if obj_name:
                    fmc_obj = self._lookup_object(obj_name)
                    if fmc_obj:
                        resolved_sources.append({
                            'type': fmc_obj.type,
                            'id': fmc_obj.id,
                            'name': fmc_obj.name
                        })
                    else:
                        resolution_issues.append(f"Source object '{obj_name}' not found in FMC")
            
            if resolved_sources:
                # Check if we exceed the limit
                if len(resolved_sources) > FMC_MAX_OBJECTS_PER_RULE:
                    print(f"  ℹ Rule '{rule_name}' has {len(resolved_sources)} source objects (>{FMC_MAX_OBJECTS_PER_RULE})")
                    group = self._create_network_group_for_rule(rule_name, resolved_sources, 'src')
                    if group:
                        resolved_rule['sourceNetworks'] = {
                            'objects': [{
                                'type': group.type,
                                'id': group.id,
                                'name': group.name
                            }]
                        }
                    else:
                        resolution_issues.append(f"Failed to create source group for {len(resolved_sources)} objects")
                        resolved_rule['sourceNetworks'] = {'objects': resolved_sources}
                else:
                    resolved_rule['sourceNetworks'] = {'objects': resolved_sources}
            else:
                del resolved_rule['sourceNetworks']
        
        # Resolve destination networks
        if 'destinationNetworks' in resolved_rule:
            resolved_dests = []
            for obj_ref in resolved_rule['destinationNetworks'].get('objects', []):
                obj_name = obj_ref.get('name')
                if obj_name:
                    fmc_obj = self._lookup_object(obj_name)
                    if fmc_obj:
                        resolved_dests.append({
                            'type': fmc_obj.type,
                            'id': fmc_obj.id,
                            'name': fmc_obj.name
                        })
                    else:
                        resolution_issues.append(f"Destination object '{obj_name}' not found in FMC")
            
            if resolved_dests:
                # Check if we exceed the limit
                if len(resolved_dests) > FMC_MAX_OBJECTS_PER_RULE:
                    print(f"  ℹ Rule '{rule_name}' has {len(resolved_dests)} destination objects (>{FMC_MAX_OBJECTS_PER_RULE})")
                    group = self._create_network_group_for_rule(rule_name, resolved_dests, 'dst')
                    if group:
                        resolved_rule['destinationNetworks'] = {
                            'objects': [{
                                'type': group.type,
                                'id': group.id,
                                'name': group.name
                            }]
                        }
                    else:
                        resolution_issues.append(f"Failed to create destination group for {len(resolved_dests)} objects")
                        resolved_rule['destinationNetworks'] = {'objects': resolved_dests}
                else:
                    resolved_rule['destinationNetworks'] = {'objects': resolved_dests}
            else:
                del resolved_rule['destinationNetworks']
        
        # Resolve services
        if 'destinationPorts' in resolved_rule:
            resolved_ports = []
            for obj_ref in resolved_rule['destinationPorts'].get('objects', []):
                if 'id' in obj_ref:
                    resolved_ports.append(obj_ref)
                else:
                    obj_name = obj_ref.get('name')
                    if obj_name:
                        fmc_obj = self._lookup_object(obj_name)
                        if fmc_obj:
                            resolved_ports.append({
                                'type': fmc_obj.type,
                                'id': fmc_obj.id,
                                'name': fmc_obj.name
                            })
                        else:
                            resolution_issues.append(f"Service '{obj_name}' not found in FMC")
            
            if resolved_ports:
                resolved_rule['destinationPorts'] = {'objects': resolved_ports}
            else:
                del resolved_rule['destinationPorts']
        
        return resolved_rule, resolution_issues
    
    def _create_access_rules(self, acp_id: str) -> bool:
        """Create access control rules with automatic group creation for large rules."""
        print("\n" + "-"*60)
        print("Creating Access Rules")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        rule_errors: List[Dict] = []
        
        for idx, policy_data in enumerate(self.plan.policies_to_create):
            policy_name = policy_data.get('wg_policy', f'Rule_{idx}')
            fmc_rule = policy_data.get('fmc_rule', {})
            
            if not fmc_rule:
                self.errors.append(f"Rule '{policy_name}': No FMC rule data generated")
                error_count += 1
                continue
            
            # Resolve object names to IDs (with automatic group creation for >200)
            resolved_rule, resolution_issues = self._resolve_rule_objects(fmc_rule, policy_data)
            
            if resolution_issues:
                for issue in resolution_issues:
                    print(f"  ⚠ [{policy_name}] {issue}")
            
            result = self.fmc.create_access_rule(acp_id, resolved_rule)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                error_detail = {
                    'policy_name': policy_name,
                    'error': error_text,
                    'resolution_issues': resolution_issues,
                    'original_rule': fmc_rule,
                    'resolved_rule': resolved_rule
                }
                rule_errors.append(error_detail)
                self.errors.append(f"Rule '{policy_name}': {error_text}")
                error_count += 1
            else:
                created_count += 1
                
                if created_count % 10 == 0:
                    print(f"  Created {created_count} rules...")
            
            time.sleep(0.15)
        
        print(f"\n✓ Created {created_count} access rules")
        if self.auto_created_groups > 0:
            print(f"ℹ Auto-created {self.auto_created_groups} network groups for rules exceeding 200 objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} rules (had planning errors)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        if rule_errors:
            self._save_rule_errors(rule_errors)
        
        return error_count == 0
    
    def _save_rule_errors(self, rule_errors: List[Dict]):
        """Save detailed rule errors to file for analysis."""
        filename = "rule_errors.json"
        try:
            with open(filename, 'w') as f:
                json.dump(rule_errors, f, indent=2, default=str)
            print(f"\n📄 Detailed rule errors saved to: {filename}")
        except Exception as e:
            print(f"\n⚠ Could not save rule errors: {e}")
    
    def _print_execution_summary(self):
        """Print execution summary."""
        print("\n" + "="*60)
        print("EXECUTION SUMMARY")
        print("="*60)
        
        print(f"\nObjects Created: {len(self.created_objects)}")
        print(f"Objects Skipped (already exist): {len(self.skipped_existing)}")
        print(f"Total Objects in Lookup: {len(self.all_objects)}")
        if self.auto_created_groups > 0:
            print(f"Auto-created Groups (for >200 object rules): {self.auto_created_groups}")
        print(f"Errors: {len(self.errors)}")
        
        if self.skipped_existing:
            print(f"\nSkipped Objects by Type:")
            type_counts = {}
            for item in self.skipped_existing:
                obj_type = item.split(']')[0].replace('[', '')
                type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
            for obj_type, count in sorted(type_counts.items()):
                print(f"  {obj_type}: {count}")
        
        true_errors = [e for e in self.errors if "already exists" not in e.lower()]
        
        if true_errors:
            print(f"\nErrors (first 20):")
            for error in true_errors[:20]:
                print(f"  - {error}")
            
            if len(true_errors) > 20:
                print(f"  ... and {len(true_errors) - 20} more errors")
                print(f"\n📄 Check rule_errors.json for detailed rule failure analysis")
