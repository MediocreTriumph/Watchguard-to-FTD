#!/usr/bin/env python3
"""
Standalone Policy Audit Script

Compares WatchGuard configuration with migrated FMC Access Control Policy
to identify missing or incomplete policy migrations.

Usage:
    python audit_migration.py watchguard_config.json \
        --fmc-host 192.168.255.20 \
        --fmc-user admin \
        --fmc-pass password \
        --acp-name "Migrated-WG-Policy" \
        --no-verify-ssl
"""

import sys
import json
import argparse
from models import WatchGuardConfig
from fmc.client import FMCClient
from migration.auditor import PolicyAuditor


def main():
    parser = argparse.ArgumentParser(
        description='Audit WatchGuard to FMC policy migration',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Required arguments
    parser.add_argument('config_file', help='Path to WatchGuard JSON config')
    
    # FMC connection
    parser.add_argument('--fmc-host', required=True, help='FMC hostname or IP')
    parser.add_argument('--fmc-user', required=True, help='FMC username')
    parser.add_argument('--fmc-pass', required=True, help='FMC password')
    parser.add_argument('--no-verify-ssl', action='store_true',
                       help='Disable SSL verification')
    
    # Audit options
    parser.add_argument('--acp-name', default='Migrated-WG-Policy',
                       help='Name of Access Control Policy to audit')
    parser.add_argument('--output', default='policy_audit_report.json',
                       help='Output file for audit report')
    
    args = parser.parse_args()
    
    try:
        # Load WatchGuard configuration
        print("="*60)
        print("LOADING WATCHGUARD CONFIGURATION")
        print("="*60)
        
        with open(args.config_file, 'r') as f:
            wg_data = json.load(f)
        
        wg_config = WatchGuardConfig.from_json(wg_data)
        print(f"\n✓ Loaded {len(wg_config.policies)} policies")
        
        # Connect to FMC
        print("\n" + "="*60)
        print("CONNECTING TO FMC")
        print("="*60)
        
        fmc_client = FMCClient(
            args.fmc_host,
            args.fmc_user,
            args.fmc_pass,
            verify_ssl=not args.no_verify_ssl
        )
        
        if not fmc_client.authenticate():
            print("\n✗ Failed to authenticate with FMC")
            sys.exit(1)
        
        print(f"\n✓ Connected to FMC")
        
        # Run audit
        auditor = PolicyAuditor(fmc_client, wg_config)
        result = auditor.audit_policy(args.acp_name)
        
        # Save report
        auditor.save_audit_report(result, args.output)
        
        # Exit with appropriate code
        sys.exit(0 if result.total_issues == 0 else 1)
        
    except Exception as e:
        print(f"\n✗ Audit failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
