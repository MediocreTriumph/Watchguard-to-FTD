"""
WatchGuard to Cisco FTD Migration Tool

A consolidated tool for migrating WatchGuard firewall configurations
to Cisco Firepower Management Center (FMC).

Key Features:
- Intelligent service object deduplication
- Canonical port mapping (prefer FMC built-ins)
- Improved application matching
- Wildcard FQDN to URL object conversion
- Clean migration to new Access Control Policy
"""

__version__ = "1.0.0"
__author__ = "Migration Tool"

from .config import MigrationConfig
from .models import WatchGuardConfig, FMCObjects

__all__ = ["MigrationConfig", "WatchGuardConfig", "FMCObjects"]
