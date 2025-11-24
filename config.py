"""
Configuration management for migration tool.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class MigrationConfig:
    """Configuration for migration process."""
    
    # Source configuration
    watchguard_config_file: str
    
    # FMC connection
    fmc_host: str
    fmc_username: str
    fmc_password: str
    fmc_domain_uuid: Optional[str] = None
    verify_ssl: bool = False
    
    # Migration settings
    new_acp_name: str = "Migrated-WatchGuard-Policy"
    prefer_builtin_objects: bool = True
    normalize_to_canonical: bool = True
    
    # Application matching
    app_match_confidence_threshold: float = 0.85
    
    # Rate limiting
    api_rate_limit_delay: float = 0.3  # seconds between API calls
    
    # Dry run mode
    dry_run: bool = True
    
    def __post_init__(self):
        """Validate configuration."""
        if self.app_match_confidence_threshold < 0.0 or self.app_match_confidence_threshold > 1.0:
            raise ValueError("Confidence threshold must be between 0.0 and 1.0")
        
        if self.api_rate_limit_delay < 0:
            raise ValueError("API rate limit delay must be non-negative")
