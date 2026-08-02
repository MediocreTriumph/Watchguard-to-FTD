"""
Migration executor - creates objects and policies in FMC.
Enhanced with unified reporting via MigrationReporter.

Updated for v5 parser with service group support.
Updated for v6 with interface discovery and zone mapping.
Updated for v7 with existing ACP support and user mapping.
"""

import time
import re
import json
import os
from typing import Dict, List, Any, Optional, Set, Tuple
from models import (
    WatchGuardAddress, WatchGuardService, WatchGuardServiceGroup,
    WatchGuardAddressGroup, FMCObject
)
from fmc.client import FMCClient
from .reporter import MigrationReporter


# FMC limit for objects per rule field
FMC_MAX_OBJECTS_PER_RULE = 200


class MigrationExecutor:
    """Executes migration plan by creating objects in FMC."""
    
    def __init__(self, fmc_client: FMCClient, plan, fmc_discovery=None,
                 zone_mapper=None, user_mapper=None, zone_resolver=None):
        self.fmc = fmc_client
        self.plan = plan
        self.fmc_discovery = fmc_discovery
        self.zone_mapper = zone_mapper
        self.user_mapper = user_mapper  # v7: optional user mapper
        self.zone_resolver = zone_resolver  # v10: explicit zone name resolution
        self.created_objects: Dict[str, FMCObject] = {}
        self.execution_log: List[str] = []
        self.errors: List[str] = []
        self.skipped_existing: List[str] = []
        self.name_map: Dict[str, str] = {}
        self.reverse_name_map: Dict[str, str] = {}
        self.used_names: Set[str] = set()
        self.auto_created_groups: int = 0
        
        # Service group tracking (v5)
        self.created_service_groups: Dict[str, FMCObject] = {}
        
        # Zone mapping statistics (v6)
        self.rules_with_zones: int = 0
        self.rules_with_zone_warnings: int = 0
        
        # User mapping statistics (v7)
        self.rules_with_users: int = 0
        self.total_users_applied: int = 0
        
        # Unified reporter
        self.reporter = MigrationReporter()
        
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
            if hasattr(self.fmc_discovery, 'port_groups'):
                for name, obj in self.fmc_discovery.port_groups.items():
                    self.all_objects[name] = obj
                    # Also register with _svc_group suffix for planner compatibility
                    svc_group_name = f"{name}_svc_group"
                    self.all_objects[svc_group_name] = obj
            if hasattr(self.fmc_discovery, 'icmp_objects'):
                for name, obj in self.fmc_discovery.icmp_objects.items():
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
    
    def _is_interface_reference(self, name: str) -> bool:
        """Check if a name refers to an interface rather than a network object.

        NOTE: only call this for names that failed object lookup. A name that
        resolves to a real object is never an interface reference, no matter
        what it's called (e.g. WatchGuard auto-generates per-policy address
        objects like 'Allow Servers to SSL VPN.1.from.1.pcy').
        """
        if self.zone_mapper:
            return self.zone_mapper.is_interface_reference(name)

        # Fallback patterns when zone_mapper not available
        interface_patterns = [
            "Any-BOVPN", "Any-MUVPN", "Any-External", "Any-Trusted",
            "Any-Optional", "Any-Multicast", "Any", "Firebox"
        ]
        if name in interface_patterns:
            return True

        # WatchGuard-specific VPN interface terms only. Deliberately NOT
        # matching bare 'vpn'/'tunnel' - those appear in legitimate object
        # names and silently dropping them breaks rules.
        name_lower = name.lower()
        if any(p in name_lower for p in ["bovpn", "muvpn"]):
            return True

        return False
    
    def _lookup_object(self, name: str) -> Optional[FMCObject]:
        """Look up an object by name using multiple strategies."""
        if name in self.all_objects:
            return self.all_objects[name]
        
        if name in self.created_objects:
            return self.created_objects[name]
        
        # Check created service groups
        if name in self.created_service_groups:
            return self.created_service_groups[name]
        
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
    
    def _is_host_mask(self, mask: str) -> bool:
        """Check if a mask represents a single host (/32)."""
        return mask in ['255.255.255.255', '32', '/32']
    
    def _is_wildcard_fqdn(self, fqdn_value: str) -> bool:
        """Check if an FQDN contains wildcards."""
        if not fqdn_value:
            return False
        return '*' in fqdn_value or fqdn_value.startswith('.')
    
    def _create_network_group_for_rule(self, rule_name: str, objects: List[Dict], 
                                        field_type: str) -> Optional[FMCObject]:
        """
        Create a network group on-the-fly for rules that exceed 200 objects.
        """
        network_objects = [obj for obj in objects if obj.get('type') != 'Url']
        url_objects = [obj for obj in objects if obj.get('type') == 'Url']
        
        if url_objects:
            print(f"    ⚠ Rule has {len(url_objects)} URL objects that cannot be grouped (FMC limitation)")
        
        if len(network_objects) <= FMC_MAX_OBJECTS_PER_RULE:
            return None
        
        base_name = f"{rule_name}_{field_type}_grp"
        group_name = self._sanitize_name(base_name)
        
        existing = self._lookup_object(group_name)
        if existing:
            return existing
        
        group_data = {
            'name': group_name,
            'type': 'NetworkGroup',
            'objects': network_objects,
            'description': f'Auto-created group for rule {rule_name} ({len(network_objects)} objects)'[:200]
        }
        
        print(f"  → Creating network group '{group_name}' for {len(network_objects)} network objects...")
        
        result = self.fmc.create_object('networkgroups', group_data)
        
        if 'error' in result:
            error_text = result.get('error', 'Unknown error')
            if self._is_already_exists_error(error_text):
                print(f"    Group '{group_name}' already exists, will use existing")
                self.reporter.group_created(group_name)
                return None
            else:
                print(f"    ✗ Failed to create group: {error_text}")
                self.reporter.group_failed(group_name, error_text, 
                                          [o.get('name', '') for o in network_objects])
                return None
        
        fmc_obj = FMCObject(
            id=result['id'],
            name=result['name'],
            type='NetworkGroup'
        )
        self.created_objects[group_name] = fmc_obj
        self.all_objects[group_name] = fmc_obj
        self.auto_created_groups += 1
        self.reporter.auto_group_created(rule_name, group_name, len(network_objects))
        
        print(f"    ✓ Created group '{group_name}' (ID: {result['id']})")
        
        return fmc_obj
    
    def execute(self, acp_name: str, use_existing_acp: bool = False) -> bool:
        """Execute the migration plan.
        
        Args:
            acp_name: Name of the ACP (to create or use existing)
            use_existing_acp: If True, look up existing ACP instead of creating new
        """
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
        
        # Create ICMP objects (v5)
        if not self._create_icmp_objects():
            success = False
        
        # Create service (port) groups (v5)
        if not self._create_service_groups():
            success = False
        
        if not self._create_network_groups():
            success = False
        
        # Get or create ACP (v7)
        if use_existing_acp:
            acp_id = self._get_existing_access_policy(acp_name)
        else:
            acp_id = self._create_access_policy(acp_name)
        
        if not acp_id:
            success = False
            self._save_reports()
            return success
        
        if not self._create_access_rules(acp_id):
            success = False
        
        self._save_reports()
        
        return success
    
    def _save_reports(self):
        """Save migration report, including zone and user mapping info if available."""
        # Add zone mapping report if available
        if self.zone_mapper:
            zone_report = self.zone_mapper.get_report()
            self.reporter.zone_mapping_report = zone_report
        
        # Add user mapping report if available (v7)
        if self.user_mapper:
            user_report = self.user_mapper.get_report()
            self.reporter.user_mapping_report = user_report
        
        self.reporter.save_report()
    
    def _create_network_objects(self) -> bool:
        """Create all network objects (hosts, networks, ranges, FQDNs - excludes URLs)."""
        print("\n" + "-"*60)
        print("Creating Network Objects")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        wildcard_count = 0
        host_from_network_count = 0
        
        for obj_def in self.plan.objects_to_create:
            obj_type = obj_def['type']
            
            if obj_type == 'url':
                continue
            
            if obj_type not in ['host', 'network', 'range', 'fqdn']:
                continue
            
            wg_obj: WatchGuardAddress = obj_def['wg_object']
            
            if obj_type == 'fqdn' and hasattr(wg_obj, 'fqdn') and self._is_wildcard_fqdn(wg_obj.fqdn):
                wildcard_count += 1
                continue
            
            if self._lookup_object(wg_obj.name):
                self.skipped_existing.append(f"[{obj_type}] {wg_obj.name}")
                self.reporter.object_skipped(obj_type, wg_obj.name, "Already exists in FMC")
                skipped_count += 1
                continue
            
            actual_type = obj_type
            if obj_type == 'network' and hasattr(wg_obj, 'mask') and wg_obj.mask:
                if self._is_host_mask(wg_obj.mask):
                    actual_type = 'host'
                    host_from_network_count += 1
            
            fmc_data = self._build_network_object_data(wg_obj, actual_type)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for {wg_obj.name}")
                self.reporter.object_failed(actual_type, wg_obj.name, "Failed to build object data")
                error_count += 1
                continue
            
            result = self.fmc.create_object(fmc_data['fmc_type'], fmc_data['data'])
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[{actual_type}] {wg_obj.name}")
                    self.reporter.object_skipped(actual_type, wg_obj.name, "Already exists in FMC")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create {wg_obj.name}: {error_text}")
                    self.reporter.object_failed(actual_type, wg_obj.name, error_text, fmc_data['data'])
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
                self.reporter.object_created(actual_type, wg_obj.name)
                created_count += 1
                
                if created_count % 50 == 0:
                    print(f"  Created {created_count} objects...")
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} network objects")
        if host_from_network_count > 0:
            print(f"ℹ Converted {host_from_network_count} /32 networks to hosts")
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
            wg_obj = obj_def['wg_object']
            
            if obj_type == 'url':
                if isinstance(wg_obj, dict):
                    name = wg_obj.get('name', '')
                    url = wg_obj.get('url', '')
                    description = wg_obj.get('description', '') or ''
                elif hasattr(wg_obj, 'fqdn') and wg_obj.fqdn:
                    name = wg_obj.name
                    url = wg_obj.fqdn
                    description = wg_obj.description if wg_obj.description else ''
                elif hasattr(wg_obj, 'name'):
                    continue
                else:
                    continue
            elif obj_type == 'fqdn':
                if not hasattr(wg_obj, 'fqdn') or not wg_obj.fqdn:
                    continue
                if not self._is_wildcard_fqdn(wg_obj.fqdn):
                    continue
                name = wg_obj.name
                url = wg_obj.fqdn
                description = wg_obj.description if wg_obj.description else ''
            else:
                continue
            
            if not name or not url:
                continue
            
            if self._lookup_object(name):
                self.skipped_existing.append(f"[url] {name}")
                self.reporter.object_skipped("url", name, "Already exists in FMC")
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
                    self.reporter.object_skipped("url", name, "Already exists in FMC")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create URL {name}: {error_text}")
                    self.reporter.object_failed("url", name, error_text, fmc_data)
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
                self.reporter.object_created("url", name)
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} URL objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _build_network_object_data(self, wg_obj: WatchGuardAddress, override_type: str = None) -> Optional[Dict]:
        """Build FMC API data for a network object."""
        obj_type = override_type or wg_obj.object_type
        sanitized_name = self._sanitize_name(wg_obj.name)
        
        if obj_type == 'host':
            ip_value = wg_obj.ip if wg_obj.ip else wg_obj.network
            return {
                'fmc_type': 'hosts',
                'data': {
                    'name': sanitized_name,
                    'type': 'Host',
                    'value': ip_value,
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
        """Create service objects for unmapped services (TCP/UDP only)."""
        print("\n" + "-"*60)
        print("Creating Service Objects (TCP/UDP)")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'service':
                continue
            
            wg_svc: WatchGuardService = obj_def['wg_object']
            
            # Skip non-TCP/UDP services (handled separately)
            if wg_svc.protocol not in ['TCP', 'UDP']:
                continue
            
            if self._lookup_object(wg_svc.name):
                self.skipped_existing.append(f"[service] {wg_svc.name}")
                self.reporter.object_skipped("service", wg_svc.name, "Already exists in FMC")
                skipped_count += 1
                continue
            
            fmc_data = self._build_service_object_data(wg_svc)
            
            if not fmc_data:
                self.errors.append(f"Failed to build data for service {wg_svc.name}")
                self.reporter.object_failed("service", wg_svc.name, "Failed to build service data")
                error_count += 1
                continue
            
            result = self.fmc.create_object(fmc_data['fmc_type'], fmc_data['data'])
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[service] {wg_svc.name}")
                    self.reporter.object_skipped("service", wg_svc.name, "Already exists in FMC")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create service {wg_svc.name}: {error_text}")
                    self.reporter.object_failed("service", wg_svc.name, error_text, fmc_data['data'])
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
                self.reporter.object_created("service", wg_svc.name)
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} service objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _create_icmp_objects(self) -> bool:
        """Create ICMP objects (v5)."""
        print("\n" + "-"*60)
        print("Creating ICMP Objects")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'service':
                continue
            
            wg_svc: WatchGuardService = obj_def['wg_object']
            
            # Only process ICMP services
            if wg_svc.protocol not in ['ICMP', 'ICMPv6']:
                continue
            
            if self._lookup_object(wg_svc.name):
                self.skipped_existing.append(f"[icmp] {wg_svc.name}")
                self.reporter.object_skipped("icmp", wg_svc.name, "Already exists in FMC")
                skipped_count += 1
                continue
            
            sanitized_name = self._sanitize_name(wg_svc.name)
            
            # Determine ICMP version
            icmp_version = getattr(wg_svc, 'icmp_version', 'v4')
            if wg_svc.protocol == 'ICMPv6':
                icmp_version = 'v6'
            
            if icmp_version == 'v6':
                fmc_type = 'icmpv6objects'
                obj_type = 'ICMPV6Object'
            else:
                fmc_type = 'icmpv4objects'
                obj_type = 'ICMPV4Object'
            
            fmc_data = {
                'name': sanitized_name,
                'type': obj_type,
                'icmpType': 'Any',  # WatchGuard doesn't specify type/code
                'description': wg_svc.description[:200] if wg_svc.description else ''
            }
            
            result = self.fmc.create_object(fmc_type, fmc_data)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[icmp] {wg_svc.name}")
                    self.reporter.object_skipped("icmp", wg_svc.name, "Already exists in FMC")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create ICMP {wg_svc.name}: {error_text}")
                    self.reporter.object_failed("icmp", wg_svc.name, error_text, fmc_data)
                    error_count += 1
            else:
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type=result['type']
                )
                self.created_objects[wg_svc.name] = fmc_obj
                self.all_objects[wg_svc.name] = fmc_obj
                self.all_objects[sanitized_name] = fmc_obj
                self.reporter.object_created("icmp", wg_svc.name)
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} ICMP objects")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _create_service_groups(self) -> bool:
        """Create service (port object) groups from v5 parser output."""
        print("\n" + "-"*60)
        print("Creating Service Groups (Port Object Groups)")
        print("-"*60)
        
        service_groups = getattr(self.plan, 'service_groups_to_create', [])
        
        if not service_groups:
            print("  No service groups to create")
            return True
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        
        for group in service_groups:
            group_name = group.name
            
            # Check if group already exists
            if self._lookup_object(group_name):
                self.skipped_existing.append(f"[service_group] {group_name}")
                self.reporter.object_skipped("service_group", group_name, "Already exists in FMC")
                skipped_count += 1
                continue
            
            # Build member objects list (TCP/UDP only - ICMP cannot be in port groups)
            member_objects = []
            missing_members = []
            
            for member_name in group.members:
                member_obj = self._lookup_object(member_name)
                if member_obj:
                    member_objects.append({
                        'type': member_obj.type,
                        'id': member_obj.id,
                        'name': member_obj.name
                    })
                else:
                    missing_members.append(member_name)
            
            if missing_members:
                print(f"  ⚠ Group '{group_name}': {len(missing_members)} members not found: {missing_members[:5]}...")
            
            if not member_objects:
                self.errors.append(f"Service group '{group_name}' has no valid members")
                self.reporter.group_failed(group_name, "No valid members found", group.members)
                error_count += 1
                continue
            
            sanitized_name = self._sanitize_name(group_name)
            
            # Build description with info about ICMP/protocol members
            desc_parts = [f"Service group for {group.original_name}"]
            if group.icmp_members:
                desc_parts.append(f"ICMP: {len(group.icmp_members)} (separate)")
            if group.protocol_members:
                desc_parts.append(f"Protocol: {len(group.protocol_members)}")
            description = " | ".join(desc_parts)[:200]
            
            fmc_data = {
                'name': sanitized_name,
                'type': 'PortObjectGroup',
                'objects': member_objects,
                'description': description
            }
            
            result = self.fmc.create_object('portobjectgroups', fmc_data)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[service_group] {group_name}")
                    self.reporter.object_skipped("service_group", group_name, "Already exists in FMC")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create service group {group_name}: {error_text}")
                    self.reporter.group_failed(group_name, error_text, group.members)
                    error_count += 1
            else:
                fmc_obj = FMCObject(
                    id=result['id'],
                    name=result['name'],
                    type='PortObjectGroup'
                )
                self.created_service_groups[group_name] = fmc_obj
                self.all_objects[group_name] = fmc_obj
                self.all_objects[sanitized_name] = fmc_obj
                
                # Report with details about non-port members
                self.reporter.service_group_created(
                    group_name, 
                    len(member_objects),
                    len(group.icmp_members),
                    len(group.protocol_members)
                )
                created_count += 1
                
                # Log warnings from the group
                for warning in group.warnings:
                    print(f"  ⚠ [{group_name}] {warning}")
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} service groups")
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
                    'icmpType': 'Any',
                    'description': wg_svc.description[:200] if wg_svc.description else ''
                }
            }
        return None
    
    def _create_network_groups(self) -> bool:
        """Create network groups from WatchGuard address groups.
        
        Updated in v6 to skip interface members and handle interface aliases.
        """
        print("\n" + "-"*60)
        print("Creating Network Groups")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        skipped_count = 0
        interface_alias_count = 0
        
        for obj_def in self.plan.objects_to_create:
            if obj_def['type'] != 'address_group':
                continue
            
            wg_group: WatchGuardAddressGroup = obj_def['wg_object']
            
            # Check if this is an interface alias (v6)
            if hasattr(wg_group, 'member_interfaces') and wg_group.member_interfaces:
                # This is an interface alias, skip it as a network group
                interface_alias_count += 1
                self.reporter.interface_alias_skipped(wg_group.name, wg_group.member_interfaces)
                continue
            
            if self._lookup_object(wg_group.name):
                self.skipped_existing.append(f"[group] {wg_group.name}")
                self.reporter.object_skipped("network_group", wg_group.name, "Already exists in FMC")
                skipped_count += 1
                continue
            
            fmc_data, skipped_members = self._build_network_group_data(wg_group)
            
            if not fmc_data:
                reason = "No valid members"
                if skipped_members:
                    reason = f"No valid members (skipped {len(skipped_members)} interface refs: {skipped_members[:3]})"
                self.errors.append(f"Failed to build data for group {wg_group.name} ({reason})")
                self.reporter.group_failed(wg_group.name, reason, wg_group.members)
                error_count += 1
                continue
            
            # Log skipped interface members
            if skipped_members:
                print(f"  ℹ Group '{wg_group.name}': skipped {len(skipped_members)} interface member(s)")
            
            result = self.fmc.create_object('networkgroups', fmc_data)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                if self._is_already_exists_error(error_text):
                    self.skipped_existing.append(f"[group] {wg_group.name}")
                    self.reporter.object_skipped("network_group", wg_group.name, "Already exists in FMC")
                    skipped_count += 1
                else:
                    self.errors.append(f"Failed to create group {wg_group.name}: {error_text}")
                    self.reporter.group_failed(wg_group.name, error_text, wg_group.members)
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
                self.reporter.group_created(wg_group.name, skipped_interface_members=skipped_members)
                created_count += 1
            
            time.sleep(0.05)
        
        print(f"\n✓ Created {created_count} network groups")
        if interface_alias_count > 0:
            print(f"ℹ Skipped {interface_alias_count} interface aliases (not network groups)")
        if skipped_count > 0:
            print(f"⚠ Skipped {skipped_count} (already exist)")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return True
    
    def _build_network_group_data(self, wg_group: WatchGuardAddressGroup) -> Tuple[Optional[Dict], List[str]]:
        """Build FMC API data for a network group.
        
        Updated in v6 to skip interface members.
        
        Returns:
            Tuple of (fmc_data, skipped_interface_members)
        """
        sanitized_name = self._sanitize_name(wg_group.name)
        
        objects = []
        skipped_interfaces = []
        
        for member_name in wg_group.members:
            # Lookup first - only treat unresolvable names as interface refs (v9)
            obj = self._lookup_object(member_name)
            if obj:
                if obj.type == 'Url':
                    continue
                objects.append({
                    'type': obj.type,
                    'id': obj.id,
                    'name': obj.name
                })
            elif self._is_interface_reference(member_name):
                skipped_interfaces.append(member_name)
        
        if not objects:
            return None, skipped_interfaces
        
        return {
            'name': sanitized_name,
            'type': 'NetworkGroup',
            'objects': objects,
            'description': wg_group.description[:200] if wg_group.description else ''
        }, skipped_interfaces
    
    def _get_existing_access_policy(self, acp_name: str) -> Optional[str]:
        """Look up an existing Access Control Policy by name or UUID.
        
        Args:
            acp_name: Name or UUID of the existing ACP
            
        Returns:
            ACP ID if found, None otherwise
        """
        print("\n" + "-"*60)
        print(f"Looking up existing Access Control Policy: {acp_name}")
        print("-"*60)
        
        policy = self.fmc.get_access_policy(acp_name)
        
        if not policy:
            self.errors.append(f"Access Control Policy not found: {acp_name}")
            print(f"✗ ACP not found: {acp_name}")
            print("\nAvailable ACPs:")
            policies = self.fmc.get_access_policies()
            for p in policies[:10]:  # Show first 10
                print(f"  - {p.get('name')} (ID: {p.get('id')})")
            if len(policies) > 10:
                print(f"  ... and {len(policies) - 10} more")
            return None
        
        acp_id = policy['id']
        acp_actual_name = policy.get('name', acp_name)
        print(f"✓ Found ACP: {acp_actual_name} (ID: {acp_id})")
        
        return acp_id
    
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
    
    def _resolve_zones_for_rule(
        self, 
        source_objects: List[Dict], 
        dest_objects: List[Dict],
        rule_name: str = ""
    ) -> Tuple[Optional[Dict], Optional[Dict], List[str]]:
        """
        Infer source/destination zones from the actual network addresses in the rule.
        """
        if not self.zone_mapper:
            return None, None, []
        
        return self.zone_mapper.infer_zones_from_networks(
            source_objects, 
            dest_objects,
            self.fmc_discovery,
            rule_name
        )
    
    def _resolve_rule_objects(self, fmc_rule: Dict, policy_data: Dict) -> Tuple[Dict, List[Dict]]:
        """Resolve object names to IDs in a rule before sending to FMC."""
        resolved_rule = dict(fmc_rule)
        warnings = []
        rule_name = fmc_rule.get('name', 'unnamed_rule')
        
        # Resolve source networks
        if 'sourceNetworks' in resolved_rule:
            resolved_sources = []
            resolved_source_urls = []
            
            for obj_ref in resolved_rule['sourceNetworks'].get('objects', []):
                obj_name = obj_ref.get('name')
                if obj_name:
                    # Lookup FIRST: a resolvable object is a real object,
                    # regardless of what its name looks like.
                    fmc_obj = self._lookup_object(obj_name)
                    if fmc_obj:
                        obj_entry = {
                            'type': fmc_obj.type,
                            'id': fmc_obj.id,
                            'name': fmc_obj.name
                        }
                        if fmc_obj.type == 'Url':
                            resolved_source_urls.append(obj_entry)
                        else:
                            resolved_sources.append(obj_entry)
                    elif self._is_interface_reference(obj_name):
                        # Unresolvable AND matches interface alias patterns:
                        # expected drop (zones handle these), skip silently.
                        continue
                    else:
                        warnings.append({
                            'type': 'unresolved',
                            'object': obj_name,
                            'field': 'source',
                            'reason': 'Not found in FMC'
                        })
            
            if resolved_sources:
                if len(resolved_sources) > FMC_MAX_OBJECTS_PER_RULE:
                    print(f"  ℹ Rule '{rule_name}' has {len(resolved_sources)} source network objects (>{FMC_MAX_OBJECTS_PER_RULE})")
                    group = self._create_network_group_for_rule(rule_name, resolved_sources, 'src')
                    if group:
                        resolved_rule['sourceNetworks'] = {
                            'objects': [{'type': group.type, 'id': group.id, 'name': group.name}]
                        }
                    else:
                        resolved_rule['sourceNetworks'] = {'objects': resolved_sources}
                else:
                    resolved_rule['sourceNetworks'] = {'objects': resolved_sources}
            else:
                del resolved_rule['sourceNetworks']
            
            if resolved_source_urls:
                print(f"  ⚠ Rule '{rule_name}' has {len(resolved_source_urls)} source URL objects (FMC doesn't support source URLs)")
        
        # Resolve destination networks
        if 'destinationNetworks' in resolved_rule:
            resolved_dests = []
            resolved_dest_urls = []
            
            for obj_ref in resolved_rule['destinationNetworks'].get('objects', []):
                obj_name = obj_ref.get('name')
                if obj_name:
                    # Lookup FIRST (see source resolution above)
                    fmc_obj = self._lookup_object(obj_name)
                    if fmc_obj:
                        obj_entry = {
                            'type': fmc_obj.type,
                            'id': fmc_obj.id,
                            'name': fmc_obj.name
                        }
                        if fmc_obj.type == 'Url':
                            resolved_dest_urls.append(obj_entry)
                        else:
                            resolved_dests.append(obj_entry)
                    elif self._is_interface_reference(obj_name):
                        continue
                    else:
                        warnings.append({
                            'type': 'unresolved',
                            'object': obj_name,
                            'field': 'destination',
                            'reason': 'Not found in FMC'
                        })
            
            if resolved_dests:
                if len(resolved_dests) > FMC_MAX_OBJECTS_PER_RULE:
                    print(f"  ℹ Rule '{rule_name}' has {len(resolved_dests)} destination network objects (>{FMC_MAX_OBJECTS_PER_RULE})")
                    group = self._create_network_group_for_rule(rule_name, resolved_dests, 'dst')
                    if group:
                        resolved_rule['destinationNetworks'] = {
                            'objects': [{'type': group.type, 'id': group.id, 'name': group.name}]
                        }
                    else:
                        resolved_rule['destinationNetworks'] = {'objects': resolved_dests}
                else:
                    resolved_rule['destinationNetworks'] = {'objects': resolved_dests}
            else:
                if 'destinationNetworks' in resolved_rule:
                    del resolved_rule['destinationNetworks']
            
            if resolved_dest_urls:
                resolved_rule['urls'] = {'objects': resolved_dest_urls}
        
        # Resolve services
        if 'destinationPorts' in resolved_rule:
            resolved_ports = []
            resolved_literals = []
            
            for obj_ref in resolved_rule['destinationPorts'].get('objects', []):
                if 'id' in obj_ref and not obj_ref.get('needs_creation'):
                    resolved_ports.append(obj_ref)
                elif obj_ref.get('is_service_group'):
                    group_name = obj_ref.get('name')
                    fmc_obj = self._lookup_object(group_name)
                    if fmc_obj:
                        resolved_ports.append({
                            'type': fmc_obj.type,
                            'id': fmc_obj.id,
                            'name': fmc_obj.name
                        })
                    else:
                        warnings.append({
                            'type': 'unresolved',
                            'object': group_name,
                            'field': 'service_group',
                            'reason': 'Service group not found in FMC'
                        })
                elif obj_ref.get('type') in ['ICMPV4Object', 'ICMPV6Object']:
                    obj_name = obj_ref.get('name')
                    fmc_obj = self._lookup_object(obj_name)
                    if fmc_obj:
                        resolved_ports.append({
                            'type': fmc_obj.type,
                            'id': fmc_obj.id,
                            'name': fmc_obj.name
                        })
                    else:
                        warnings.append({
                            'type': 'unresolved',
                            'object': obj_name,
                            'field': 'icmp',
                            'reason': 'ICMP object not found in FMC'
                        })
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
                            warnings.append({
                                'type': 'unresolved',
                                'object': obj_name,
                                'field': 'service',
                                'reason': 'Not found in FMC'
                            })
            
            for literal in resolved_rule['destinationPorts'].get('literals', []):
                resolved_literals.append(literal)
            
            if resolved_ports or resolved_literals:
                resolved_rule['destinationPorts'] = {}
                if resolved_ports:
                    resolved_rule['destinationPorts']['objects'] = resolved_ports
                if resolved_literals:
                    resolved_rule['destinationPorts']['literals'] = resolved_literals
            else:
                del resolved_rule['destinationPorts']
        
        # Check for unmapped applications
        unmapped_apps = policy_data.get('applications_unmapped', [])
        app_action = policy_data.get('app_action_original', '')
        for app_name in unmapped_apps:
            warnings.append({
                'type': 'unmapped_app',
                'application': app_name,
                'app_action': app_action
            })
        
        # Check for unmapped users (v7)
        unmapped_users = policy_data.get('users_unmapped', [])
        for user_name in unmapped_users:
            warnings.append({
                'type': 'unmapped_user',
                'user': user_name
            })
        
        # Explicit zones from the plan (v10) - take precedence over inference
        explicit_src_zones = policy_data.get('source_zones') or []
        explicit_dst_zones = policy_data.get('destination_zones') or []
        applied_explicit = False

        if (explicit_src_zones or explicit_dst_zones) and self.zone_resolver:
            src_refs = self.zone_resolver.resolve_all(explicit_src_zones)
            dst_refs = self.zone_resolver.resolve_all(explicit_dst_zones)

            if src_refs:
                resolved_rule['sourceZones'] = {'objects': src_refs}
            if dst_refs:
                resolved_rule['destinationZones'] = {'objects': dst_refs}
            if src_refs or dst_refs:
                self.rules_with_zones += 1
                applied_explicit = True

            for missing in (set(explicit_src_zones) - {r['name'] for r in src_refs}) | \
                           (set(explicit_dst_zones) - {r['name'] for r in dst_refs}):
                warnings.append({
                    'type': 'zone_mapping',
                    'message': f"Zone '{missing}' not found in FMC - create it and re-run, "
                               f"or fix the name in the zone mappings file"
                })
        elif (explicit_src_zones or explicit_dst_zones) and not self.zone_resolver:
            warnings.append({
                'type': 'zone_mapping',
                'message': 'Plan specifies zones but no zone resolver available'
            })

        # Zone inference (v6.3) - fallback for rules without explicit zones
        if not applied_explicit and self.zone_mapper:
            resolved_sources = resolved_rule.get('sourceNetworks', {}).get('objects', [])
            resolved_dests = resolved_rule.get('destinationNetworks', {}).get('objects', [])

            source_zone, dest_zone, zone_warnings = self._resolve_zones_for_rule(
                resolved_sources, resolved_dests, rule_name
            )

            if source_zone:
                resolved_rule['sourceZones'] = {'objects': [source_zone]}
                self.rules_with_zones += 1

            if dest_zone:
                resolved_rule['destinationZones'] = {'objects': [dest_zone]}
                if not source_zone:
                    self.rules_with_zones += 1

            for zw in zone_warnings:
                warnings.append({
                    'type': 'zone_mapping',
                    'message': zw
                })

        return resolved_rule, warnings
    
    def _create_access_rules(self, acp_id: str) -> bool:
        """Create access control rules."""
        print("\n" + "-"*60)
        print("Creating Access Rules")
        print("-"*60)
        
        created_count = 0
        error_count = 0
        rules_with_apps = 0
        rules_with_service_groups = 0
        total_apps_applied = 0
        
        for idx, policy_data in enumerate(self.plan.policies_to_create):
            policy_name = policy_data.get('wg_policy', f'Rule_{idx}')
            fmc_rule = policy_data.get('fmc_rule', {})
            
            if not fmc_rule:
                self.errors.append(f"Rule '{policy_name}': No FMC rule data generated")
                self.reporter.rule_failed(policy_name, "No FMC rule data generated")
                error_count += 1
                continue
            
            if 'applications' in fmc_rule:
                app_count = len(fmc_rule['applications'].get('applications', []))
                if app_count > 0:
                    rules_with_apps += 1
                    total_apps_applied += app_count
            
            if policy_data.get('uses_service_group'):
                rules_with_service_groups += 1
            
            # Track user statistics (v7)
            if 'users' in fmc_rule:
                user_count = len(fmc_rule['users'].get('objects', []))
                if user_count > 0:
                    self.rules_with_users += 1
                    self.total_users_applied += user_count
            
            resolved_rule, rule_warnings = self._resolve_rule_objects(fmc_rule, policy_data)
            
            has_warnings = len(rule_warnings) > 0
            missing_elements = []
            
            for warning in rule_warnings:
                if warning['type'] == 'unresolved':
                    self.reporter.rule_warning_unresolved(
                        policy_name, warning['object'], warning['field'],
                        warning.get('reason', 'Not found in FMC')
                    )
                    field = warning['field']
                    if field == 'source' and 'source_networks' not in missing_elements:
                        missing_elements.append('source_networks')
                    elif field == 'destination' and 'destination_networks' not in missing_elements:
                        missing_elements.append('destination_networks')
                    elif field in ['service', 'service_group', 'icmp'] and 'services' not in missing_elements:
                        missing_elements.append('services')
                elif warning['type'] == 'unmapped_app':
                    self.reporter.rule_warning_unmapped_app(
                        policy_name, warning['application'],
                        warning.get('app_action', 'Unknown')
                    )
                    if 'applications' not in missing_elements:
                        missing_elements.append('applications')
                elif warning['type'] == 'unmapped_user':
                    # Log unmapped user warning (v7)
                    self.reporter.rule_warning_unmapped_user(
                        policy_name, warning.get('user', 'Unknown')
                    )
                    print(f"  ⚠ [{policy_name}] unmapped_user: {warning.get('user', 'Unknown')}")
                    if 'users' not in missing_elements:
                        missing_elements.append('users')
                elif warning['type'] == 'zone_mapping':
                    print(f"  ⚠ [{policy_name}] zone: {warning.get('message', 'Unknown')}")
                    continue
                
                if warning['type'] not in ['zone_mapping', 'unmapped_user']:
                    print(f"  ⚠ [{policy_name}] {warning['type']}: {warning.get('object', warning.get('application', 'Unknown'))}")
            
            result = self.fmc.create_access_rule(acp_id, resolved_rule)
            
            if 'error' in result:
                error_text = result.get('error', 'Unknown error')
                self.errors.append(f"Rule '{policy_name}': {error_text}")
                self.reporter.rule_failed(policy_name, error_text, fmc_rule, resolved_rule)
                error_count += 1
            else:
                if missing_elements:
                    self.reporter.rule_incomplete(policy_name, missing_elements, created=True)
                
                self.reporter.rule_created(policy_name, has_warnings=has_warnings)
                created_count += 1
                
                if created_count % 10 == 0:
                    print(f"  Created {created_count} rules...")
            
            time.sleep(0.15)
        
        print(f"\n✓ Created {created_count} access rules")
        if rules_with_apps > 0:
            print(f"ℹ {rules_with_apps} rules have applications ({total_apps_applied} total app references)")
        if rules_with_service_groups > 0:
            print(f"ℹ {rules_with_service_groups} rules use service groups")
        if self.rules_with_users > 0:
            print(f"ℹ {self.rules_with_users} rules have users ({self.total_users_applied} total user references)")
        if self.rules_with_zones > 0:
            print(f"ℹ {self.rules_with_zones} rules have zone mappings")
        if self.auto_created_groups > 0:
            print(f"ℹ Auto-created {self.auto_created_groups} network groups for rules exceeding 200 objects")
        if error_count > 0:
            print(f"✗ {error_count} errors")
        
        return error_count == 0
