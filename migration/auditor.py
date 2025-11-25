"""
Policy Audit Module - Compares WatchGuard config with migrated FMC policy.

This module fetches the migrated Access Control Policy from FMC and compares it
against the original WatchGuard configuration to identify:
- Missing policies/rules
- Incomplete policy migrations
- Missing object references
- Mapping discrepancies
"""

import json
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass, field
from models import WatchGuardConfig, WatchGuardPolicy
from fmc.client import FMCClient


@dataclass
class PolicyAuditResult:
    """Results of policy audit."""
    
    # Policy comparison
    total_wg_policies: int = 0
    migrated_policies: int = 0
    missing_policies: List[str] = field(default_factory=list)
    
    # Object reference issues
    missing_source_objects: Dict[str, List[str]] = field(default_factory=dict)  # policy -> [objects]
    missing_dest_objects: Dict[str, List[str]] = field(default_factory=dict)
    missing_services: Dict[str, List[str]] = field(default_factory=dict)
    missing_applications: Dict[str, List[str]] = field(default_factory=dict)
    
    # Mapping issues
    unmapped_policies: List[str] = field(default_factory=list)
    incomplete_policies: List[str] = field(default_factory=list)
    
    # Summary stats
    total_issues: int = 0
    
    def calculate_totals(self):
        """Calculate total issues."""
        self.total_issues = (
            len(self.missing_policies) +
            len(self.missing_source_objects) +
            len(self.missing_dest_objects) +
            len(self.missing_services) +
            len(self.missing_applications) +
            len(self.unmapped_policies) +
            len(self.incomplete_policies)
        )


class PolicyAuditor:
    """Audits migrated FMC policy against WatchGuard configuration."""
    
    def __init__(self, fmc_client: FMCClient, wg_config: WatchGuardConfig):
        self.fmc = fmc_client
        self.wg_config = wg_config
        self.fmc_policy_id: Optional[str] = None
        self.fmc_rules: List[Dict] = []
        self.fmc_objects: Dict[str, Any] = {}
    
    def audit_policy(self, acp_name: str) -> PolicyAuditResult:
        """
        Perform comprehensive policy audit.
        
        Args:
            acp_name: Name of the Access Control Policy to audit
            
        Returns:
            PolicyAuditResult with detailed findings
        """
        print("\n" + "="*60)
        print("POLICY AUDIT")
        print("="*60)
        
        result = PolicyAuditResult()
        result.total_wg_policies = len(self.wg_config.policies)
        
        # Step 1: Find the ACP
        print(f"\nSearching for Access Control Policy: {acp_name}")
        if not self._find_access_policy(acp_name):
            print(f"✗ Policy '{acp_name}' not found in FMC")
            result.missing_policies = [p.name for p in self.wg_config.policies]
            result.calculate_totals()
            return result
        
        print(f"✓ Found policy (ID: {self.fmc_policy_id})")
        
        # Step 2: Fetch all access rules
        print("\nFetching access rules from FMC...")
        self._fetch_access_rules()
        print(f"✓ Retrieved {len(self.fmc_rules)} rules")
        
        # Step 3: Fetch FMC objects for reference checking
        print("\nFetching FMC objects for validation...")
        self._fetch_fmc_objects()
        
        # Step 4: Compare policies
        print("\nComparing WatchGuard policies with FMC rules...")
        self._compare_policies(result)
        
        # Step 5: Check object references
        print("\nValidating object references...")
        self._validate_object_references(result)
        
        # Calculate totals
        result.calculate_totals()
        
        # Print summary
        self._print_audit_summary(result)
        
        return result
    
    def _find_access_policy(self, acp_name: str) -> bool:
        """Find the Access Control Policy by name."""
        endpoint = f"{self.fmc.base_url}/domain/{self.fmc.domain_uuid}/policy/accesspolicies"
        
        response = self.fmc._make_request('GET', endpoint, params={'expanded': True})
        
        if response.status_code != 200:
            return False
        
        data = response.json()
        for policy in data.get('items', []):
            if policy['name'] == acp_name:
                self.fmc_policy_id = policy['id']
                return True
        
        return False
    
    def _fetch_access_rules(self):
        """Fetch all access rules from the policy."""
        if not self.fmc_policy_id:
            return
        
        endpoint = f"{self.fmc.base_url}/domain/{self.fmc.domain_uuid}/policy/accesspolicies/{self.fmc_policy_id}/accessrules"
        
        # Fetch paginated
        self.fmc_rules = self.fmc.get_paginated(endpoint, limit=1000)
    
    def _fetch_fmc_objects(self):
        """Fetch FMC objects for reference validation."""
        print("  Fetching hosts...")
        self.fmc_objects['hosts'] = {obj['name']: obj for obj in self.fmc.get_objects('hosts')}
        
        print("  Fetching networks...")
        self.fmc_objects['networks'] = {obj['name']: obj for obj in self.fmc.get_objects('networks')}
        
        print("  Fetching ranges...")
        self.fmc_objects['ranges'] = {obj['name']: obj for obj in self.fmc.get_objects('ranges')}
        
        print("  Fetching FQDNs...")
        self.fmc_objects['fqdns'] = {obj['name']: obj for obj in self.fmc.get_objects('fqdns')}
        
        print("  Fetching network groups...")
        self.fmc_objects['networkgroups'] = {obj['name']: obj for obj in self.fmc.get_objects('networkgroups')}
        
        print("  Fetching port objects...")
        self.fmc_objects['ports'] = {obj['name']: obj for obj in self.fmc.get_objects('protocolportobjects')}
        
        print("  Fetching applications...")
        self.fmc_objects['applications'] = {obj['name']: obj for obj in self.fmc.get_objects('applications')}
    
    def _compare_policies(self, result: PolicyAuditResult):
        """Compare WatchGuard policies with FMC rules."""
        # Build a map of FMC rule names
        fmc_rule_names = {rule['name'] for rule in self.fmc_rules}
        
        # Check each WatchGuard policy
        for wg_policy in self.wg_config.policies:
            # Truncate to FMC's 50 character limit for comparison
            wg_policy_name = wg_policy.name[:50]
            
            if wg_policy_name in fmc_rule_names:
                result.migrated_policies += 1
            else:
                # Check if disabled
                if not wg_policy.enabled:
                    continue  # Skip disabled policies
                
                result.missing_policies.append(wg_policy.name)
    
    def _validate_object_references(self, result: PolicyAuditResult):
        """Validate that all object references in rules exist in FMC."""
        for rule in self.fmc_rules:
            rule_name = rule['name']
            
            # Check source networks
            source_nets = rule.get('sourceNetworks', {}).get('objects', [])
            for obj in source_nets:
                if not self._object_exists(obj['name'], obj['type']):
                    if rule_name not in result.missing_source_objects:
                        result.missing_source_objects[rule_name] = []
                    result.missing_source_objects[rule_name].append(obj['name'])
            
            # Check destination networks
            dest_nets = rule.get('destinationNetworks', {}).get('objects', [])
            for obj in dest_nets:
                if not self._object_exists(obj['name'], obj['type']):
                    if rule_name not in result.missing_dest_objects:
                        result.missing_dest_objects[rule_name] = []
                    result.missing_dest_objects[rule_name].append(obj['name'])
            
            # Check destination ports (services)
            dest_ports = rule.get('destinationPorts', {}).get('objects', [])
            for obj in dest_ports:
                if not self._object_exists(obj['name'], obj['type']):
                    if rule_name not in result.missing_services:
                        result.missing_services[rule_name] = []
                    result.missing_services[rule_name].append(obj['name'])
            
            # Check applications
            apps = rule.get('applications', {}).get('applications', [])
            for obj in apps:
                if not self._object_exists(obj['name'], 'Application'):
                    if rule_name not in result.missing_applications:
                        result.missing_applications[rule_name] = []
                    result.missing_applications[rule_name].append(obj['name'])
    
    def _object_exists(self, name: str, obj_type: str) -> bool:
        """Check if an object exists in FMC."""
        type_map = {
            'Host': 'hosts',
            'Network': 'networks',
            'Range': 'ranges',
            'FQDN': 'fqdns',
            'NetworkGroup': 'networkgroups',
            'ProtocolPortObject': 'ports',
            'Application': 'applications'
        }
        
        collection_name = type_map.get(obj_type)
        if not collection_name:
            return True  # Unknown type, assume exists
        
        collection = self.fmc_objects.get(collection_name, {})
        return name in collection
    
    def _print_audit_summary(self, result: PolicyAuditResult):
        """Print audit summary."""
        print("\n" + "="*60)
        print("AUDIT SUMMARY")
        print("="*60)
        
        print(f"\nPolicy Coverage:")
        print(f"  Total WG Policies:    {result.total_wg_policies}")
        print(f"  Migrated to FMC:      {result.migrated_policies}")
        print(f"  Missing from FMC:     {len(result.missing_policies)}")
        
        if result.missing_policies:
            print(f"\n  Missing Policies (first 10):")
            for policy in result.missing_policies[:10]:
                print(f"    - {policy}")
            if len(result.missing_policies) > 10:
                print(f"    ... and {len(result.missing_policies) - 10} more")
        
        print(f"\nObject Reference Issues:")
        print(f"  Rules with missing sources:      {len(result.missing_source_objects)}")
        print(f"  Rules with missing destinations: {len(result.missing_dest_objects)}")
        print(f"  Rules with missing services:     {len(result.missing_services)}")
        print(f"  Rules with missing applications: {len(result.missing_applications)}")
        
        if result.missing_source_objects:
            print(f"\n  Sample Missing Source Objects:")
            for rule, objs in list(result.missing_source_objects.items())[:3]:
                print(f"    Rule '{rule}':")
                for obj in objs[:3]:
                    print(f"      - {obj}")
        
        if result.missing_services:
            print(f"\n  Sample Missing Services:")
            for rule, objs in list(result.missing_services.items())[:3]:
                print(f"    Rule '{rule}':")
                for obj in objs[:3]:
                    print(f"      - {obj}")
        
        print(f"\n{'='*60}")
        print(f"Total Issues Found: {result.total_issues}")
        print(f"{'='*60}")
    
    def save_audit_report(self, result: PolicyAuditResult, filename: str = "policy_audit_report.json"):
        """Save audit report to JSON file."""
        report = {
            'summary': {
                'total_wg_policies': result.total_wg_policies,
                'migrated_policies': result.migrated_policies,
                'missing_policies_count': len(result.missing_policies),
                'total_issues': result.total_issues
            },
            'missing_policies': result.missing_policies,
            'missing_source_objects': result.missing_source_objects,
            'missing_dest_objects': result.missing_dest_objects,
            'missing_services': result.missing_services,
            'missing_applications': result.missing_applications,
            'unmapped_policies': result.unmapped_policies,
            'incomplete_policies': result.incomplete_policies
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✓ Audit report saved to: {filename}")
