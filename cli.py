#!/usr/bin/env python3
"""
WatchGuard to Cisco FTD Migration Tool - CLI Entry Point

Updated for v6 with interface discovery and zone mapping.
Updated for v7 with existing ACP support and user mapping.
"""

import sys
import json
import argparse
from pathlib import Path

from config import MigrationConfig
from models import WatchGuardConfig
from fmc.client import FMCClient
from fmc.discovery import FMCDiscovery
from fmc.canonical import CanonicalPortMapper
from fmc.zones import ZoneMapper
from fmc.user_mapper import UserMapper
from analysis.service_mapper import ServiceMapper
from analysis.app_mapper import ApplicationMapper
from migration.planner import MigrationPlanner
from migration.executor import MigrationExecutor


def main():
    parser = argparse.ArgumentParser(
        description='Migrate WatchGuard configuration to Cisco FMC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Dry run (default) - builds plan but doesn't create anything
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --fmc-pass password --dry-run

  # Execute migration to a NEW Access Control Policy
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --fmc-pass password --execute \\
      --new-acp "Migrated-WG-Policy"
      
  # Execute migration to an EXISTING Access Control Policy
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --fmc-pass password --execute \\
      --existing-acp "My-Existing-Policy"
      
  # Execute with zone mapping (assumes INSIDE/OUTSIDE zones exist)
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --fmc-pass password --execute \\
      --new-acp "Migrated-WG-Policy" --enable-zones
      
  # Execute with user mapping (requires identity policy/realm configured)
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --fmc-pass password --execute \\
      --existing-acp "My-Existing-Policy" --enable-users
        '''
    )
    
    # Required arguments
    parser.add_argument('config_file', help='Path to parsed WatchGuard JSON config')
    
    # FMC connection
    parser.add_argument('--fmc-host', required=True, help='FMC hostname or IP')
    parser.add_argument('--fmc-user', required=True, help='FMC username')
    parser.add_argument('--fmc-pass', required=True, help='FMC password')
    parser.add_argument('--no-verify-ssl', action='store_true', 
                       help='Disable SSL verification (for self-signed certs)')
    
    # Migration options - mutually exclusive ACP options
    acp_group = parser.add_mutually_exclusive_group()
    acp_group.add_argument('--new-acp', default=None,
                       help='Name for new Access Control Policy to create')
    acp_group.add_argument('--existing-acp',
                       help='Name or UUID of existing Access Control Policy to add rules to')
    parser.add_argument('--execute', action='store_true',
                       help='Execute migration (default is dry-run)')
    parser.add_argument('--dry-run', action='store_true', default=True,
                       help='Dry run mode - build plan but don\'t create objects')
    
    # Zone mapping options (v6)
    parser.add_argument('--enable-zones', action='store_true',
                       help='Enable interface-to-zone mapping (requires INSIDE/OUTSIDE zones in FMC)')
    
    # User mapping options (v7)
    parser.add_argument('--enable-users', action='store_true',
                       help='Enable user mapping from WatchGuard aliases to FMC realm users')
    parser.add_argument('--user-confidence', type=float, default=0.85,
                       help='User matching confidence threshold (default: 0.85)')
    
    # Matching options
    parser.add_argument('--app-confidence', type=float, default=0.85,
                       help='Application matching confidence threshold (default: 0.85)')
    
    args = parser.parse_args()
    
    # Determine ACP name - default to creating new if neither specified
    acp_name = args.new_acp or args.existing_acp or 'Migrated-WG-Policy'
    use_existing_acp = args.existing_acp is not None
    
    # Build configuration
    config = MigrationConfig(
        watchguard_config_file=args.config_file,
        fmc_host=args.fmc_host,
        fmc_username=args.fmc_user,
        fmc_password=args.fmc_pass,
        verify_ssl=not args.no_verify_ssl,
        new_acp_name=acp_name,
        dry_run=not args.execute,
        app_match_confidence_threshold=args.app_confidence
    )
    
    # Run migration
    try:
        success = run_migration(
            config, 
            enable_zones=args.enable_zones, 
            use_existing_acp=use_existing_acp,
            enable_users=args.enable_users,
            user_confidence=args.user_confidence
        )
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def run_migration(config: MigrationConfig, enable_zones: bool = False,
                  use_existing_acp: bool = False, enable_users: bool = False,
                  user_confidence: float = 0.85) -> bool:
    """Run the migration process."""
    
    print("="*60)
    print("WATCHGUARD TO CISCO FTD MIGRATION TOOL")
    print("="*60)
    print(f"\nMode: {'DRY RUN' if config.dry_run else 'EXECUTE'}")
    print(f"Source: {config.watchguard_config_file}")
    print(f"Target: {config.fmc_host}")
    if use_existing_acp:
        print(f"Existing ACP: {config.new_acp_name}")
    else:
        print(f"New ACP: {config.new_acp_name}")
    if enable_zones:
        print(f"Zone Mapping: ENABLED")
    if enable_users:
        print(f"User Mapping: ENABLED")
    
    # Step 1: Load WatchGuard configuration
    print("\n" + "="*60)
    print("STEP 1: LOADING WATCHGUARD CONFIGURATION")
    print("="*60)
    
    with open(config.watchguard_config_file, 'r') as f:
        wg_data = json.load(f)
    
    wg_config = WatchGuardConfig.from_json(wg_data)
    
    print(f"\n✓ Loaded WatchGuard configuration")
    print(f"  Hosts:          {len(wg_config.hosts)}")
    print(f"  Networks:       {len(wg_config.networks)}")
    print(f"  Ranges:         {len(wg_config.ranges)}")
    print(f"  FQDNs:          {len(wg_config.fqdns)}")
    print(f"  TCP Services:   {len(wg_config.tcp_services)}")
    print(f"  UDP Services:   {len(wg_config.udp_services)}")
    print(f"  Policies:       {len(wg_config.policies)}")
    print(f"  App Actions:    {len(wg_config.app_actions)}")
    
    # Check for interfaces in the config
    interfaces_count = len(wg_data.get('interfaces', []))
    interface_aliases_count = len(wg_data.get('interface_aliases', []))
    if interfaces_count > 0:
        print(f"  Interfaces:     {interfaces_count}")
    if interface_aliases_count > 0:
        print(f"  Interface Aliases: {interface_aliases_count}")
    
    # Count users in address groups
    all_users = set()
    for group in wg_config.address_groups:
        if group.member_users:
            all_users.update(group.member_users)
    if all_users:
        print(f"  Users in groups: {len(all_users)}")
    
    # Step 2: Connect to FMC
    print("\n" + "="*60)
    print("STEP 2: CONNECTING TO FMC")
    print("="*60)
    
    fmc_client = FMCClient(
        config.fmc_host,
        config.fmc_username,
        config.fmc_password,
        config.verify_ssl
    )
    
    if not fmc_client.authenticate():
        print("\n✗ Failed to authenticate with FMC")
        return False
    
    print(f"\n✓ Connected to FMC")
    print(f"  Domain UUID: {fmc_client.domain_uuid}")
    
    # Step 3: Discover existing FMC objects
    print("\n" + "="*60)
    print("STEP 3: DISCOVERING FMC OBJECTS")
    print("="*60)
    
    discovery = FMCDiscovery(fmc_client)
    fmc_objects = discovery.discover_all()
    
    # Step 3.5: Zone Mapping (v6.3) - if enabled
    zone_mapper = None
    if enable_zones:
        print("\n" + "="*60)
        print("STEP 3.5: ZONE MAPPING")
        print("="*60)
        
        zone_mapper = ZoneMapper(fmc_client)
        
        # Discover FMC zones
        zones_ok = zone_mapper.discover_fmc_zones()
        if not zones_ok:
            print("  ⚠ Expected zones (INSIDE/OUTSIDE) not found - zone mapping disabled")
            zone_mapper = None
        else:
            # Load WatchGuard object values for zone inference
            zone_mapper.load_wg_object_values(wg_config)
            
            # Print summary
            zone_mapper.print_summary()
    
    # Step 3.6: User Mapping (v7) - if enabled
    user_mapper = None
    if enable_users and all_users:
        print("\n" + "="*60)
        print("STEP 3.6: USER MAPPING")
        print("="*60)
        
        user_mapper = UserMapper(fmc_client, confidence_threshold=user_confidence)
        
        # Discover realms and users
        realms_ok = user_mapper.discover_realms()
        if not realms_ok:
            print("  ⚠ No identity realms found - user mapping disabled")
            user_mapper = None
        else:
            # Map WatchGuard users to FMC realm users
            user_mapper.map_users(list(all_users))
            user_mapper.print_summary()
    elif enable_users and not all_users:
        print("\n  ℹ User mapping enabled but no users found in WatchGuard config")
    
    # Step 4: Build canonical port mappings
    print("\n" + "="*60)
    print("STEP 4: BUILDING CANONICAL MAPPINGS")
    print("="*60)
    
    canonical_mapper = CanonicalPortMapper(fmc_objects)
    canon_stats = canonical_mapper.get_statistics()
    
    print(f"\n✓ Canonical port mappings built")
    print(f"  Unique ports:   {canon_stats['total_unique_ports']}")
    print(f"  Built-in:       {canon_stats['builtin_objects']}")
    print(f"  Custom:         {canon_stats['custom_objects']}")
    
    # Store canonical mappings in fmc_objects for easy access
    fmc_objects.canonical_ports = canonical_mapper.canonical_map
    
    # Step 5: Map services
    print("\n" + "="*60)
    print("STEP 5: MAPPING SERVICES")
    print("="*60)
    
    service_mapper = ServiceMapper(fmc_objects, canonical_mapper)
    all_services = wg_config.tcp_services + wg_config.udp_services
    service_mapper.map_services(all_services)
    
    # Step 6: Map applications
    print("\n" + "="*60)
    print("STEP 6: MAPPING APPLICATIONS")
    print("="*60)
    
    # Extract unique app names from app actions
    unique_apps = set()
    for app_action in wg_config.app_actions:
        unique_apps.update(app_action.allowed_apps)
        unique_apps.update(app_action.blocked_apps)
    
    print(f"  Found {len(unique_apps)} unique applications in {len(wg_config.app_actions)} app actions")
    
    app_mapper = ApplicationMapper(fmc_objects, config.app_match_confidence_threshold)
    app_mapper.map_applications(sorted(unique_apps))
    
    # Step 7: Build migration plan
    print("\n" + "="*60)
    print("STEP 7: BUILDING MIGRATION PLAN")
    print("="*60)
    
    planner = MigrationPlanner(wg_config, fmc_objects, service_mapper, app_mapper,
                               user_mapper=user_mapper)
    plan = planner.build_plan()
    
    # Step 8: Save plan to file
    print("\n" + "="*60)
    print("SAVING MIGRATION PLAN")
    print("="*60)
    
    plan_file = "migration_plan.json"
    save_migration_plan(plan, plan_file, zone_mapper, user_mapper)
    print(f"\n✓ Migration plan saved to: {plan_file}")
    
    # Show application mapping summary
    policies_with_apps = plan.statistics.get('policies_with_applications', 0)
    if policies_with_apps > 0:
        print(f"  Policies with applications: {policies_with_apps}")
    
    # Show user mapping summary
    policies_with_users = plan.statistics.get('policies_with_users', 0)
    if policies_with_users > 0:
        print(f"  Policies with users: {policies_with_users}")
    
    if config.dry_run:
        print("\n" + "="*60)
        print("DRY RUN COMPLETE")
        print("="*60)
        print("\nNo objects were created in FMC.")
        print("Review the migration plan and run with --execute to proceed.")
        return True
    
    # Step 9: Execute migration
    print("\n" + "="*60)
    print("STEP 8: EXECUTING MIGRATION")
    print("="*60)
    print("\n⚠  This will create objects in FMC")
    
    # Pass fmc_objects, zone_mapper, and user_mapper to executor
    executor = MigrationExecutor(fmc_client, plan, fmc_discovery=fmc_objects,
                                  zone_mapper=zone_mapper, user_mapper=user_mapper)
    success = executor.execute(config.new_acp_name, use_existing_acp=use_existing_acp)
    
    return success


def save_migration_plan(plan, filename: str, zone_mapper=None, user_mapper=None):
    """Save migration plan to JSON file."""
    # Convert plan to serializable format
    plan_data = {
        'statistics': {
            'total_wg_objects': plan.total_wg_objects,
            'mapped_to_existing': plan.mapped_to_existing,
            'needs_creation': plan.needs_creation,
            'unmapped': plan.unmapped,
            'policies_with_applications': plan.statistics.get('policies_with_applications', 0),
            'policies_with_users': plan.statistics.get('policies_with_users', 0)
        },
        'address_mappings': {
            name: {'id': obj.id, 'name': obj.name, 'type': obj.type}
            for name, obj in plan.address_mappings.items()
        },
        'service_mappings': {
            name: {'id': obj.id, 'name': obj.name, 'type': obj.type, 
                   'protocol': obj.protocol, 'port': obj.port}
            for name, obj in plan.service_mappings.items()
        },
        'app_mappings': {
            name: {'id': obj.id, 'name': obj.name, 'type': obj.type}
            for name, obj in plan.app_mappings.items()
        },
        'objects_to_create': len(plan.objects_to_create),
        'policies_to_create': len(plan.policies_to_create),
        'warnings': plan.warnings,
        'errors': plan.errors
    }
    
    # Add zone mapping data if available (v6)
    if zone_mapper:
        plan_data['zone_mapping'] = zone_mapper.get_report()
    
    # Add user mapping data if available (v7)
    if user_mapper:
        plan_data['user_mapping'] = user_mapper.get_report()
    
    with open(filename, 'w') as f:
        json.dump(plan_data, f, indent=2)


if __name__ == '__main__':
    main()
