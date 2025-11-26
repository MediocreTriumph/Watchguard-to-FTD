"""
Migration executor - creates objects and policies in FMC.
Enhanced with better logging, duplicate detection, and proper ID resolution.
"""

import time
import re
import json
from typing import Dict, List, Any, Optional, Set
from models import (
    WatchGuardAddress, WatchGuardService, 
    WatchGuardAddressGroup, FMCObject
)
from fmc.client import FMCClient


class MigrationExecutor:
    """Executes migration plan by creating objects in FMC."""
    
    def __init__(self, fmc_client: FMCClient, plan, fmc_discovery=None):
        self.fmc = fmc_client
        self.plan = plan
        self.fmc_discovery = fmc_discovery  # FMCObjects from discovery
        self.created_objects: Dict[str, FMCObject] = {}
        self.execution_log: List[str] = []
        self.errors: List[str] = []
        self.skipped_existing: List[str] = []  # Track objects that already exist
        self.name_map: Dict[str, str] = {}  # original_name -> sanitized_name
        self.used_names: Set[str] = set()  # Track used names to avoid collisions
        
        # Master object lookup: name -> FMCObject (combines discovered + created)
        self.all_objects: Dict[str, FMCObject] = {}
        self._build_object_lookup()
    
    def _build_object_lookup(self):
        """Build master object lookup from discovered FMC objects."""
        if self.fmc_discovery:
            # Add all discovered objects to lookup
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
        
        # Add service mappings from plan
        if hasattr(self.plan, 'service_mappings'):
            for name, obj in self.plan.service_mappings.items():
                self.all_objects[name] = obj
        
        print(f"\n  Object lookup initialized with {len(self.all_objects)} objects")
    
    def _sanitize_name(self, name: str) -> str:
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
        
        self.name_map[name] = sanitized
        self.used_names.add(sanitized)
        
        return sanitized
    
    def _is_already_exists_error(self, error_text: str) -> bool:
        """Check if error is 'already exists' type."""
        if not error_text:
            return False
        return "already exists" in error_text.lower()
    
    def _lookup_object(self, name: str) -> Optional[FMCObject]:
        """Look up an object by name (original or sanitized)."""
        # Try original name
        if name in self.all_objects:
            return self.all_objects[name]
        
        # Try sanitized name
        sanitized = self._sanitize_name(name)
        if sanitized in self.all_objects:
            return self.all_objects[sanitized]
        
        # Try created objects
        if name in self.created_objects:
            return self.created_objects[name]
        
        return None
    
    def execute(self, acp_name: str) -> bool:
        """Execute the migration plan."""
        print("\n" + "="*60)
        print("EXECUTING MIGRATION")
        print("="*60)
        
        success = True
        
        # Step 1: Create network objects
        if not self._create_network_objects():
            success = False
        
        # Step 2: Create service objects
        if not self._create_service_objects():
            success = False
        
        # Step 3: Create network groups
        if not self._create_network_groups():
            success = False
        
        # Step 4: Create Access Control Policy
        acp_id = self._create_access_policy(acp_name)
        if not acp_id:
            success = False
            return success
        
        # Step 5: Create access rules (with ID resolution)
        if not self._create_access_rules(acp_id):
            success = False
        
        # Print summary
        self._print_execution_summary()
        
        return success
    
    def _create_network_objects(self) -> bool:
        """Create all network objects (hosts, networks, ranges, FQDNs)."""
        print("\n" + "-"*60)
        print("Creating Network Objects")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for obj_def in self.plan.objects_to_create:
            obj_type = obj_def['type']
            
            if obj_type not in ['host', 'network', 'range', 'fqdn']:
                continue
            
            wg_obj: WatchGuardAddress = obj_def['wg_object']
            
            # Skip if object already exists in FMC
            if wg_obj.name in self.all_objects:
                self.skipped_existing.append(f"[{obj_type}] {wg_obj.name}")
                skipped_count += 1
                continue
            
            # Build FMC object data
            fmc_data = self._build_network_object_data(wg_obj)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for {wg_obj.name}")
                error_count += 1
                continue
            
            # Create in FMC
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
                # Store created object
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type']
                )
                self.created_objects[wg_obj.name] = fmc_obj
                self.all_objects[wg_obj.name] = fmc_obj  # Add to master lookup
                created_count += 1
                
                if created_count % 50 == 0:
                    print(f"  Created {created_count} objects...")
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} network objects")
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
            
            # Skip if already mapped
            if wg_svc.name in self.all_objects:
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
        """Create network groups."""
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
            
            if wg_group.name in self.all_objects:
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
    
    def _resolve_rule_objects(self, fmc_rule: Dict, policy_data: Dict) -> Dict:
        """
        Resolve object names to IDs in a rule before sending to FMC.
        This is the critical step that was missing!
        """
        resolved_rule = dict(fmc_rule)
        resolution_issues = []
        
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
                resolved_rule['sourceNetworks'] = {'objects': resolved_sources}
            else:
                # Remove empty sourceNetworks
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
                resolved_rule['destinationNetworks'] = {'objects': resolved_dests}
            else:
                del resolved_rule['destinationNetworks']
        
        # Services should already have IDs from service_mappings, but verify
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
        """Create access control rules in the policy with proper ID resolution."""
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
            
            # CRITICAL: Resolve object names to IDs
            resolved_rule, resolution_issues = self._resolve_rule_objects(fmc_rule, policy_data)
            
            if resolution_issues:
                # Log but don't skip - try to create anyway with what we have
                for issue in resolution_issues:
                    print(f"  ⚠ [{policy_name}] {issue}")
            
            # Create the rule
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
        print(f"Errors: {len(self.errors)}")
        
        if self.skipped_existing:
            print(f"\nSkipped Objects by Type:")
            type_counts = {}
            for item in self.skipped_existing:
                obj_type = item.split(']')[0].replace('[', '')
                type_counts[obj_type] = type_counts.get(obj_type, 0) + 1
            for obj_type, count in sorted(type_counts.items()):
                print(f"  {obj_type}: {count}")
        
        # Filter out "already exists" from true errors
        true_errors = [e for e in self.errors if "already exists" not in e.lower()]
        
        if true_errors:
            print(f"\nErrors (first 20):")
            for error in true_errors[:20]:
                print(f"  - {error}")
            
            if len(true_errors) > 20:
                print(f"  ... and {len(true_errors) - 20} more errors")
                print(f"\n📄 Check rule_errors.json for detailed rule failure analysis")
