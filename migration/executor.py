"""
Migration executor - creates objects and policies in FMC.
"""

import time
import re
from typing import Dict, List, Any, Optional
from models import (
    MigrationPlan, WatchGuardAddress, WatchGuardService, 
    WatchGuardAddressGroup, FMCObject
)
from fmc.client import FMCClient


class MigrationExecutor:
    """Executes migration plan by creating objects in FMC."""
    
    def __init__(self, fmc_client: FMCClient, plan: MigrationPlan):
        self.fmc = fmc_client
        self.plan = plan
        self.created_objects: Dict[str, FMCObject] = {}
        self.execution_log: List[str] = []
        self.errors: List[str] = []
        self.name_map: Dict[str, str] = {}  # original_name -> sanitized_name
        self.used_names: set = set()  # Track used names to avoid collisions
    
    def _sanitize_name(self, name: str) -> str:
        """
        Sanitize object name to be FMC-compliant.
        
        FMC object names cannot contain: : ? * < > | / \\ or spaces
        and must be <= 50 characters.
        """
        # Check if already sanitized
        if name in self.name_map:
            return self.name_map[name]
        
        # Remove/replace invalid characters
        sanitized = name
        
        # Replace colons, question marks, asterisks, spaces, etc. with underscores
        invalid_chars = r'[:?*<>|/\\\s]'
        sanitized = re.sub(invalid_chars, '_', sanitized)
        
        # Remove leading/trailing underscores
        sanitized = sanitized.strip('_')
        
        # Collapse multiple consecutive underscores into one
        sanitized = re.sub(r'_+', '_', sanitized)
        
        # Limit to 50 characters
        if len(sanitized) > 50:
            sanitized = sanitized[:50].rstrip('_')
        
        # Handle empty names
        if not sanitized:
            sanitized = "unnamed_object"
        
        # Handle name collisions by appending number
        original_sanitized = sanitized
        counter = 1
        while sanitized in self.used_names:
            # Add counter, keeping total length <= 50
            suffix = f"_{counter}"
            max_base_len = 50 - len(suffix)
            sanitized = original_sanitized[:max_base_len] + suffix
            counter += 1
        
        # Store mapping and mark as used
        self.name_map[name] = sanitized
        self.used_names.add(sanitized)
        
        return sanitized
    
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
        
        # Step 5: Create access rules
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
        
        for obj_def in self.plan.objects_to_create:
            obj_type = obj_def['type']
            
            if obj_type not in ['host', 'network', 'range', 'fqdn']:
                continue
            
            wg_obj: WatchGuardAddress = obj_def['wg_object']
            
            # Build FMC object data
            fmc_data = self._build_network_object_data(wg_obj)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for {wg_obj.name}")
                error_count += 1
                continue
            
            # Create in FMC
            result = self.fmc.create_object(fmc_data['fmc_type'], fmc_data['data'])
            
            if 'error' in result:
                self.errors.append(f"Failed to create {wg_obj.name}: {result.get('error', 'Unknown error')}")
                error_count += 1
            else:
                # Store created object
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type']
                )
                self.created_objects[wg_obj.name] = fmc_obj
                created_count += 1
                
                if created_count % 10 == 0:
                    print(f"  Created {created_count} objects...")
            
            # Rate limiting
            time.sleep(0.1)
        
        print(f"\n✓ Created {created_count} network objects")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return error_count == 0
    
    def _build_network_object_data(self, wg_obj: WatchGuardAddress) -> Optional[Dict]:
        """Build FMC API data for a network object."""
        obj_type = wg_obj.object_type
        
        # Sanitize the name
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
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'service':
                continue
            
            wg_svc: WatchGuardService = obj_def['wg_object']
            
            # Build FMC object data
            fmc_data = self._build_service_object_data(wg_svc)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for service {wg_svc.name}")
                error_count += 1
                continue
            
            # Create in FMC
            result = self.fmc.create_object(fmc_data['fmc_type'], fmc_data['data'])
            
            if 'error' in result:
                self.errors.append(f"Failed to create service {wg_svc.name}: {result.get('error', 'Unknown error')}")
                error_count += 1
            else:
                # Store created object
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type'],
                    protocol=wg_svc.protocol,
                    port=wg_svc.port
                )
                self.created_objects[wg_svc.name] = fmc_obj
                created_count += 1
            
            # Rate limiting
            time.sleep(0.1)
        
        print(f"\n✓ Created {created_count} service objects")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return error_count == 0
    
    def _build_service_object_data(self, wg_svc: WatchGuardService) -> Optional[Dict]:
        """Build FMC API data for a service object."""
        # Sanitize the name
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
            # ICMP objects need special handling
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
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'address_group':
                continue
            
            wg_group: WatchGuardAddressGroup = obj_def['wg_object']
            
            # Build FMC object data
            fmc_data = self._build_network_group_data(wg_group)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for group {wg_group.name}")
                error_count += 1
                continue
            
            # Create in FMC
            result = self.fmc.create_object('networkgroups', fmc_data)
            
            if 'error' in result:
                self.errors.append(f"Failed to create group {wg_group.name}: {result.get('error', 'Unknown error')}")
                error_count += 1
            else:
                # Store created object
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type']
                )
                self.created_objects[wg_group.name] = fmc_obj
                created_count += 1
            
            # Rate limiting
            time.sleep(0.1)
        
        print(f"\n✓ Created {created_count} network groups")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return error_count == 0
    
    def _build_network_group_data(self, wg_group: WatchGuardAddressGroup) -> Optional[Dict]:
        """Build FMC API data for a network group."""
        # Sanitize the name
        sanitized_name = self._sanitize_name(wg_group.name)
        
        # Resolve member references to FMC objects
        objects = []
        
        for member_name in wg_group.members:
            # Check if we created this object
            if member_name in self.created_objects:
                obj = self.created_objects[member_name]
                objects.append({
                    'type': obj.type,
                    'id': obj.id,
                    'name': obj.name
                })
            # Check if it exists in plan mappings
            elif member_name in self.plan.address_mappings:
                obj = self.plan.address_mappings[member_name]
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
    
    def _create_access_rules(self, acp_id: str) -> bool:
        """Create access control rules in the policy."""
        print("\n" + "-"*60)
        print("Creating Access Rules")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for policy_data in self.plan.policies_to_create:
            # Skip policies with errors
            if policy_data.get('errors'):
                skipped_count += 1
                continue
            
            fmc_rule = policy_data['fmc_rule']
            
            # Create the rule
            result = self.fmc.create_access_rule(acp_id, fmc_rule)
            
            if 'error' in result:
                self.errors.append(f"Failed to create rule {fmc_rule['name']}: {result.get('error', 'Unknown error')}")
                error_count += 1
            else:
                created_count += 1
                
                if created_count % 10 == 0:
                    print(f"  Created {created_count} rules...")
            
            # Rate limiting
            time.sleep(0.2)
        
        print(f"\n✓ Created {created_count} access rules")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} rules (had errors)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return error_count == 0
    
    def _print_execution_summary(self):
        """Print execution summary."""
        print("\n" + "="*60)
        print("EXECUTION SUMMARY")
        print("="*60)
        
        print(f"\nObjects Created: {len(self.created_objects)}")
        print(f"Errors: {len(self.errors)}")
        
        # Print name sanitization stats
        sanitized_count = len(self.name_map)
        if sanitized_count > 0:
            print(f"\nName Sanitization:")
            print(f"  Names sanitized: {sanitized_count}")
            
            # Show a few examples
            print(f"  Examples (first 5):")
            for i, (original, sanitized) in enumerate(list(self.name_map.items())[:5]):
                if original != sanitized:
                    print(f"    '{original}' → '{sanitized}'")
        
        if self.errors:
            print("\nErrors (first 20):")
            for error in self.errors[:20]:
                print(f"  - {error}")
            
            if len(self.errors) > 20:
                print(f"  ... and {len(self.errors) - 20} more errors")
