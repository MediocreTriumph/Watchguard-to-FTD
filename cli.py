#!/usr/bin/env python3
"""
WatchGuard to Cisco FTD Migration Tool - CLI Entry Point

Updated for v6 with interface discovery and zone mapping.
Updated for v7 with existing ACP support and user mapping.
Updated for v8 with manual application mappings support.
"""

import os
import sys
import json
import getpass
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
from migration import planfile


def main():
    parser = argparse.ArgumentParser(
        description='Migrate WatchGuard configuration to Cisco FMC',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Password: supply via the FMC_PASSWORD environment variable, or omit
--fmc-pass to be prompted interactively. Avoid --fmc-pass on the command
line (visible in shell history and process lists).

Examples:
  # Dry run (default) - builds plan but doesn't create anything
  export FMC_PASSWORD='...'
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin

  # Execute migration to a NEW Access Control Policy
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --execute \\
      --new-acp "Migrated-WG-Policy"
      
  # Execute migration to an EXISTING Access Control Policy
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --execute \\
      --existing-acp "My-Existing-Policy"
      
  # Execute with zone mapping (assumes INSIDE/OUTSIDE zones exist)
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --execute \\
      --new-acp "Migrated-WG-Policy" --enable-zones
      
  # Execute with user mapping (requires identity policy/realm configured)
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --execute \\
      --existing-acp "My-Existing-Policy" --enable-users
      
  # Execute with manual application mappings
  python cli.py watchguard_config.json --fmc-host 192.168.255.122 \\
      --fmc-user admin --execute \\
      --new-acp "Migrated-WG-Policy" --app-mappings app_mappings.json

Application Mappings File Format (JSON):
  {
    "mappings": {
      "WatchGuard App Name": "FMC Application Name",
      "Outlook.com": "Outlook",
      "iTunes/App Store": "iTunes"
    }
  }
        '''
    )
    
    # Required arguments
    parser.add_argument('config_file', nargs='?', default=None,
                       help='Path to parsed WatchGuard JSON config '
                            '(omit when using --from-plan)')

    # Plan file execution (v9)
    parser.add_argument('--from-plan', default=None, metavar='PLAN_FILE',
                       help='Execute from a previously saved migration_plan.json '
                            'instead of re-planning. The plan file may be '
                            'hand-edited (e.g. remove rules) before execution.')
    
    # FMC connection (not required for --from-plan validation without --execute)
    parser.add_argument('--fmc-host', default=None, help='FMC hostname or IP')
    parser.add_argument('--fmc-user', default=None, help='FMC username')
    parser.add_argument('--fmc-pass', default=None,
                       help='FMC password (prefer FMC_PASSWORD env var or '
                            'interactive prompt; passing on the command line '
                            'exposes it in shell history and process lists)')
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Disable SSL verification (for self-signed certs)')
    
    # Migration options - mutually exclusive ACP options
    acp_group = parser.add_mutually_exclusive_group()
    acp_group.add_argument('--new-acp', default=None,
                       help='Name for new Access Control Policy to create')
    acp_group.add_argument('--existing-acp',
                       help='Name or UUID of existing Access Control Policy to add rules to')
    parser.add_argument('--execute', action='store_true',
                       help='Execute migration (default is dry-run: build plan '
                            'but don\'t create objects)')
    parser.add_argument('--include-management', action='store_true',
                       help='Also migrate management-plane and default-deny '
                            'policies (WatchGuard Web UI, Ping To Firebox, '
                            'Unhandled Packet rules, etc.). Skipped by default '
                            'because FTD handles these outside the ACP.')

    # Zone mapping options (v6)
    parser.add_argument('--enable-zones', action='store_true',
                       help='Enable interface-to-zone mapping (zones must exist in FMC)')
    parser.add_argument('--zone-inside', default='INSIDE',
                       help='Name of FMC security zone for internal networks (default: INSIDE)')
    parser.add_argument('--zone-outside', default='OUTSIDE',
                       help='Name of FMC security zone for external networks (default: OUTSIDE)')
    
    # User mapping options (v7)
    parser.add_argument('--enable-users', action='store_true',
                       help='Enable user mapping from WatchGuard aliases to FMC realm users')
    parser.add_argument('--user-confidence', type=float, default=0.85,
                       help='User matching confidence threshold (default: 0.85)')
    
    # Application matching options (v8)
    parser.add_argument('--app-confidence', type=float, default=0.85,
                       help='Application matching confidence threshold (default: 0.85)')
    parser.add_argument('--app-mappings', type=str, default=None,
                       help='Path to JSON file with manual application mappings')
    
    args = parser.parse_args()

    # Validate input source: parsed config XOR plan file
    if not args.from_plan and not args.config_file:
        parser.error('config_file is required (or use --from-plan PLAN_FILE)')
    if args.from_plan and args.config_file:
        parser.error('give either config_file or --from-plan, not both')

    # Plan-file validation mode needs no FMC connection at all
    if args.from_plan and not args.execute:
        sys.exit(0 if validate_plan_file(args.from_plan) else 1)

    # Every other mode talks to FMC
    if not args.fmc_host or not args.fmc_user:
        parser.error('--fmc-host and --fmc-user are required')

    # Resolve password: --fmc-pass > FMC_PASSWORD env var > interactive prompt
    fmc_password = args.fmc_pass or os.environ.get('FMC_PASSWORD')
    if not fmc_password:
        fmc_password = getpass.getpass('FMC password: ')

    # Determine ACP name - default to creating new if neither specified
    acp_name = args.new_acp or args.existing_acp or 'Migrated-WG-Policy'
    use_existing_acp = args.existing_acp is not None

    # Build configuration
    config = MigrationConfig(
        watchguard_config_file=args.config_file or args.from_plan,
        fmc_host=args.fmc_host,
        fmc_username=args.fmc_user,
        fmc_password=fmc_password,
        verify_ssl=not args.no_verify_ssl,
        new_acp_name=acp_name,
        dry_run=not args.execute,
        app_match_confidence_threshold=args.app_confidence
    )
    
    # Run migration
    try:
        if args.from_plan:
            success = run_from_plan(
                config,
                plan_file=args.from_plan,
                use_existing_acp=use_existing_acp,
                enable_zones=args.enable_zones,
                zone_inside=args.zone_inside,
                zone_outside=args.zone_outside
            )
        else:
            success = run_migration(
                config,
                enable_zones=args.enable_zones,
                use_existing_acp=use_existing_acp,
                enable_users=args.enable_users,
                user_confidence=args.user_confidence,
                app_mappings_file=args.app_mappings,
                zone_inside=args.zone_inside,
                zone_outside=args.zone_outside,
                include_management=args.include_management
            )
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n✗ Migration failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def validate_plan_file(plan_file: str) -> bool:
    """Load and summarize a plan file without touching FMC."""
    print("="*60)
    print("VALIDATING PLAN FILE")
    print("="*60)
    try:
        plan = planfile.load_plan(plan_file)
    except (ValueError, KeyError, TypeError, OSError) as e:
        print(f"\n✗ Plan file invalid: {e}")
        return False

    print(f"\n✓ Plan file is valid: {plan_file}")
    print(f"  Objects to create:  {len(plan.objects_to_create)}")
    print(f"  Service groups:     {len(plan.service_groups_to_create)}")
    print(f"  Policies to create: {len(plan.policies_to_create)}")
    skipped = [s for s in plan.skipped_policies if not s.get('included')]
    if skipped:
        print(f"  Policies skipped at planning time: {len(skipped)}")
    if plan.errors:
        print(f"  ⚠ Plan contains {len(plan.errors)} errors - review before executing")
    print("\nRun with --execute to apply this plan to FMC.")
    return True


def _connect_fmc(config: MigrationConfig):
    """Connect and authenticate to FMC. Returns client or None."""
    fmc_client = FMCClient(
        config.fmc_host,
        config.fmc_username,
        config.fmc_password,
        config.verify_ssl
    )
    if not fmc_client.authenticate():
        print("\n✗ Failed to authenticate with FMC")
        return None
    print(f"\n✓ Connected to FMC")
    print(f"  Domain UUID: {fmc_client.domain_uuid}")
    return fmc_client


def run_from_plan(config: MigrationConfig, plan_file: str,
                  use_existing_acp: bool = False, enable_zones: bool = False,
                  zone_inside: str = 'INSIDE', zone_outside: str = 'OUTSIDE') -> bool:
    """Execute a previously saved (and possibly hand-edited) plan file."""
    print("="*60)
    print("WATCHGUARD TO CISCO FTD MIGRATION TOOL - EXECUTE FROM PLAN")
    print("="*60)
    print(f"\nPlan file: {plan_file}")
    print(f"Target: {config.fmc_host}")

    plan = planfile.load_plan(plan_file)
    print(f"\n✓ Loaded plan")
    print(f"  Objects to create:  {len(plan.objects_to_create)}")
    print(f"  Policies to create: {len(plan.policies_to_create)}")

    fmc_client = _connect_fmc(config)
    if not fmc_client:
        return False

    discovery = FMCDiscovery(fmc_client)
    fmc_objects = discovery.discover_all()

    # Optional zone mapping: rebuild object values from the plan itself
    zone_mapper = None
    if enable_zones:
        zone_mapper = ZoneMapper(fmc_client, inside_zone=zone_inside,
                                 outside_zone=zone_outside)
        if not zone_mapper.discover_fmc_zones():
            print(f"  ⚠ Expected zones ({zone_inside}/{zone_outside}) not found - zone mapping disabled")
            zone_mapper = None
        else:
            addresses = [e['wg_object'] for e in plan.objects_to_create
                         if hasattr(e['wg_object'], 'object_type')]

            class _PlanAddresses:
                hosts = addresses
                networks = addresses
                ranges = addresses

            zone_mapper.load_wg_object_values(_PlanAddresses())
            zone_mapper.print_summary()

    print("\n⚠  This will create objects in FMC")
    executor = MigrationExecutor(fmc_client, plan, fmc_discovery=fmc_objects,
                                 zone_mapper=zone_mapper, user_mapper=None)
    return executor.execute(config.new_acp_name, use_existing_acp=use_existing_acp)


def run_migration(config: MigrationConfig, enable_zones: bool = False,
                  use_existing_acp: bool = False, enable_users: bool = False,
                  user_confidence: float = 0.85, app_mappings_file: str = None,
                  zone_inside: str = 'INSIDE', zone_outside: str = 'OUTSIDE',
                  include_management: bool = False) -> bool:
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
    if app_mappings_file:
        print(f"App Mappings File: {app_mappings_file}")
    
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
        
        zone_mapper = ZoneMapper(fmc_client, inside_zone=zone_inside,
                                 outside_zone=zone_outside)

        # Discover FMC zones
        zones_ok = zone_mapper.discover_fmc_zones()
        if not zones_ok:
            print(f"  ⚠ Expected zones ({zone_inside}/{zone_outside}) not found - zone mapping disabled")
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
    
    # Create app mapper with optional manual mappings file
    app_mapper = ApplicationMapper(
        fmc_objects, 
        config.app_match_confidence_threshold,
        manual_mappings_file=app_mappings_file
    )
    app_mapper.map_applications(sorted(unique_apps))
    
    # Step 7: Build migration plan
    print("\n" + "="*60)
    print("STEP 7: BUILDING MIGRATION PLAN")
    print("="*60)
    
    planner = MigrationPlanner(wg_config, fmc_objects, service_mapper, app_mapper,
                               user_mapper=user_mapper,
                               include_management=include_management)
    plan = planner.build_plan()
    
    # Step 8: Save plan to file
    print("\n" + "="*60)
    print("STEP 8: SAVING MIGRATION PLAN")
    print("="*60)
    
    plan_file = "migration_plan.json"
    extra_reports = {}
    if zone_mapper:
        extra_reports['zone_mapping'] = zone_mapper.get_report()
    if user_mapper:
        extra_reports['user_mapping'] = user_mapper.get_report()
    if app_mapper and hasattr(app_mapper, 'get_report'):
        extra_reports['application_mapping'] = app_mapper.get_report()

    planfile.save_plan(
        plan, plan_file,
        metadata={
            'source_config': config.watchguard_config_file,
            'fmc_host': config.fmc_host,
            'acp_name': config.new_acp_name,
            'use_existing_acp': use_existing_acp,
            'include_management': include_management,
        },
        extra_reports=extra_reports or None
    )
    print(f"\n✓ Migration plan saved to: {plan_file}")

    skipped = [s for s in plan.skipped_policies if not s.get('included')]
    if skipped:
        print(f"  Policies skipped by classification: {len(skipped)} "
              f"(rerun with --include-management to migrate them)")
    
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
        print("Review (and optionally edit) the migration plan, then either")
        print("re-run with --execute, or run: cli.py --from-plan migration_plan.json --execute")
        return True

    # Step 9: Execute migration
    print("\n" + "="*60)
    print("STEP 9: EXECUTING MIGRATION")
    print("="*60)
    print("\n⚠  This will create objects in FMC")

    # Execute from the saved plan file (round-trip) so the file on disk is
    # always a faithful, executable record of what was migrated.
    plan = planfile.load_plan(plan_file)

    executor = MigrationExecutor(fmc_client, plan, fmc_discovery=fmc_objects,
                                  zone_mapper=zone_mapper, user_mapper=user_mapper)
    success = executor.execute(config.new_acp_name, use_existing_acp=use_existing_acp)

    return success


if __name__ == '__main__':
    main()
