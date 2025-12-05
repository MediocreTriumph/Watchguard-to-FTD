"""
User Mapper - Maps WatchGuard users to FMC Realm Users.

WatchGuard stores users in aliases/groups as "DOMAIN\\username" format.
FMC stores realm users with realm references and various name formats.

This module handles the fuzzy matching between the two systems.
"""

import re
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from difflib import SequenceMatcher


@dataclass
class RealmUser:
    """FMC Realm User reference."""
    id: str
    name: str
    realm_id: str
    realm_name: str
    type: str = "RealUser"
    
    # Original data from FMC for debugging
    raw_data: Optional[Dict] = None


@dataclass
class RealmUserGroup:
    """FMC Realm User Group reference."""
    id: str
    name: str
    realm_id: str
    realm_name: str
    type: str = "RealUserGroup"


@dataclass 
class UserMapping:
    """Result of mapping a WatchGuard user to FMC."""
    wg_user: str  # Original WatchGuard user string (e.g., "DOMAIN\username")
    fmc_user: Optional[RealmUser]  # Matched FMC user, or None
    match_confidence: float  # 0.0 to 1.0
    match_method: str  # How the match was made (exact, normalized, fuzzy)
    warnings: List[str] = field(default_factory=list)


class UserMapper:
    """
    Maps WatchGuard users to FMC Realm Users.
    
    WatchGuard user formats:
    - "DOMAIN\\username"
    - "DOMAIN\\First Last"
    - "username@domain.com"
    - "username"
    
    FMC realm user formats vary by identity source configuration.
    """
    
    def __init__(self, fmc_client, confidence_threshold: float = 0.85):
        """
        Initialize the user mapper.
        
        Args:
            fmc_client: FMCClient instance
            confidence_threshold: Minimum confidence for fuzzy matches (0.0-1.0)
        """
        self.fmc = fmc_client
        self.confidence_threshold = confidence_threshold
        
        # Discovered realms and users
        self.realms: Dict[str, Dict] = {}  # realm_id -> realm_data
        self.realm_users: Dict[str, List[RealmUser]] = {}  # realm_id -> users
        self.realm_groups: Dict[str, List[RealmUserGroup]] = {}  # realm_id -> groups
        
        # Lookup indexes for fast matching
        self._user_by_name: Dict[str, RealmUser] = {}  # lowercase name -> user
        self._user_by_normalized: Dict[str, RealmUser] = {}  # normalized name -> user
        self._group_by_name: Dict[str, RealmUserGroup] = {}
        
        # Mapping results
        self.user_mappings: Dict[str, UserMapping] = {}  # wg_user -> mapping
        
        # Statistics
        self.stats = {
            'total_realms': 0,
            'total_realm_users': 0,
            'total_realm_groups': 0,
            'wg_users_found': 0,
            'exact_matches': 0,
            'normalized_matches': 0,
            'fuzzy_matches': 0,
            'unmatched': 0
        }
    
    def discover_realms(self) -> bool:
        """
        Discover all realms and their users from FMC.
        
        Returns:
            True if at least one realm was found
        """
        print("\n" + "-"*60)
        print("Discovering Identity Realms")
        print("-"*60)
        
        realms = self.fmc.get_realms()
        
        if not realms:
            print("  ⚠ No identity realms configured in FMC")
            print("  User mapping will be skipped")
            return False
        
        self.stats['total_realms'] = len(realms)
        print(f"  Found {len(realms)} realm(s)")
        
        for realm in realms:
            realm_id = realm['id']
            realm_name = realm.get('name', 'Unknown')
            
            self.realms[realm_id] = realm
            print(f"\n  Realm: {realm_name} (ID: {realm_id})")
            
            # Discover users in this realm
            users = self.fmc.get_realm_users(realm_id)
            self.realm_users[realm_id] = []
            
            for user_data in users:
                user = RealmUser(
                    id=user_data['id'],
                    name=user_data.get('name', ''),
                    realm_id=realm_id,
                    realm_name=realm_name,
                    raw_data=user_data
                )
                self.realm_users[realm_id].append(user)
                
                # Build lookup indexes
                name_lower = user.name.lower()
                self._user_by_name[name_lower] = user
                
                # Also index by normalized name (no domain prefix)
                normalized = self._normalize_username(user.name)
                self._user_by_normalized[normalized] = user
            
            self.stats['total_realm_users'] += len(users)
            print(f"    Users: {len(users)}")
            
            # Discover groups in this realm
            groups = self.fmc.get_realm_user_groups(realm_id)
            self.realm_groups[realm_id] = []
            
            for group_data in groups:
                group = RealmUserGroup(
                    id=group_data['id'],
                    name=group_data.get('name', ''),
                    realm_id=realm_id,
                    realm_name=realm_name
                )
                self.realm_groups[realm_id].append(group)
                self._group_by_name[group.name.lower()] = group
            
            self.stats['total_realm_groups'] += len(groups)
            print(f"    Groups: {len(groups)}")
        
        return True
    
    def _normalize_username(self, username: str) -> str:
        """
        Normalize a username for matching.
        
        Handles various formats:
        - "DOMAIN\\username" -> "username"
        - "username@domain.com" -> "username"
        - "First Last" -> "first last"
        - Removes special characters
        """
        if not username:
            return ""
        
        normalized = username.lower().strip()
        
        # Remove domain prefix (DOMAIN\username)
        if '\\' in normalized:
            normalized = normalized.split('\\')[-1]
        
        # Remove domain suffix (username@domain.com)
        if '@' in normalized:
            normalized = normalized.split('@')[0]
        
        return normalized
    
    def _extract_domain(self, username: str) -> Optional[str]:
        """Extract domain from a username string."""
        if '\\' in username:
            return username.split('\\')[0].upper()
        if '@' in username:
            parts = username.split('@')
            if len(parts) > 1:
                # Return first part of domain (e.g., "corp" from "corp.example.com")
                return parts[1].split('.')[0].upper()
        return None
    
    def map_users(self, wg_users: List[str]) -> Dict[str, UserMapping]:
        """
        Map a list of WatchGuard users to FMC realm users.
        
        Args:
            wg_users: List of WatchGuard user strings
            
        Returns:
            Dict mapping WatchGuard user -> UserMapping
        """
        if not self.realms:
            print("  ⚠ No realms discovered - skipping user mapping")
            return {}
        
        self.stats['wg_users_found'] = len(wg_users)
        
        for wg_user in wg_users:
            mapping = self._map_single_user(wg_user)
            self.user_mappings[wg_user] = mapping
            
            # Update stats
            if mapping.fmc_user:
                if mapping.match_method == 'exact':
                    self.stats['exact_matches'] += 1
                elif mapping.match_method == 'normalized':
                    self.stats['normalized_matches'] += 1
                elif mapping.match_method == 'fuzzy':
                    self.stats['fuzzy_matches'] += 1
            else:
                self.stats['unmatched'] += 1
        
        return self.user_mappings
    
    def _map_single_user(self, wg_user: str) -> UserMapping:
        """Map a single WatchGuard user to FMC."""
        warnings = []
        
        # Try exact match first (case-insensitive)
        wg_lower = wg_user.lower()
        if wg_lower in self._user_by_name:
            return UserMapping(
                wg_user=wg_user,
                fmc_user=self._user_by_name[wg_lower],
                match_confidence=1.0,
                match_method='exact'
            )
        
        # Try normalized match (strip domain)
        normalized = self._normalize_username(wg_user)
        if normalized in self._user_by_normalized:
            return UserMapping(
                wg_user=wg_user,
                fmc_user=self._user_by_normalized[normalized],
                match_confidence=0.95,
                match_method='normalized'
            )
        
        # Try fuzzy matching
        best_match = None
        best_score = 0.0
        
        for fmc_name, fmc_user in self._user_by_normalized.items():
            score = SequenceMatcher(None, normalized, fmc_name).ratio()
            if score > best_score and score >= self.confidence_threshold:
                best_score = score
                best_match = fmc_user
        
        if best_match:
            warnings.append(f"Fuzzy match: '{wg_user}' -> '{best_match.name}' ({best_score:.0%})")
            return UserMapping(
                wg_user=wg_user,
                fmc_user=best_match,
                match_confidence=best_score,
                match_method='fuzzy',
                warnings=warnings
            )
        
        # No match found
        warnings.append(f"No FMC realm user found for '{wg_user}'")
        return UserMapping(
            wg_user=wg_user,
            fmc_user=None,
            match_confidence=0.0,
            match_method='none',
            warnings=warnings
        )
    
    def get_fmc_user_ref(self, wg_user: str) -> Optional[Dict]:
        """
        Get FMC API reference dict for a WatchGuard user.
        
        Args:
            wg_user: WatchGuard user string
            
        Returns:
            Dict suitable for FMC API 'users' field, or None
        """
        if wg_user not in self.user_mappings:
            return None
        
        mapping = self.user_mappings[wg_user]
        if not mapping.fmc_user:
            return None
        
        return {
            'type': 'RealUser',
            'id': mapping.fmc_user.id,
            'name': mapping.fmc_user.name,
            'realm': {
                'id': mapping.fmc_user.realm_id,
                'name': mapping.fmc_user.realm_name,
                'type': 'Realm'
            }
        }
    
    def print_summary(self):
        """Print user mapping summary."""
        print("\n" + "-"*60)
        print("User Mapping Summary")
        print("-"*60)
        print(f"  Realms discovered:    {self.stats['total_realms']}")
        print(f"  FMC realm users:      {self.stats['total_realm_users']}")
        print(f"  FMC realm groups:     {self.stats['total_realm_groups']}")
        print(f"\n  WatchGuard users:     {self.stats['wg_users_found']}")
        print(f"    Exact matches:      {self.stats['exact_matches']}")
        print(f"    Normalized matches: {self.stats['normalized_matches']}")
        print(f"    Fuzzy matches:      {self.stats['fuzzy_matches']}")
        print(f"    Unmatched:          {self.stats['unmatched']}")
        
        # Show some unmatched users
        unmatched = [u for u, m in self.user_mappings.items() if not m.fmc_user]
        if unmatched:
            print(f"\n  Unmatched users (first 5):")
            for u in unmatched[:5]:
                print(f"    - {u}")
            if len(unmatched) > 5:
                print(f"    ... and {len(unmatched) - 5} more")
    
    def get_report(self) -> Dict:
        """Get a report dict for inclusion in migration output."""
        return {
            'realms': [
                {'id': r['id'], 'name': r.get('name', '')}
                for r in self.realms.values()
            ],
            'statistics': self.stats,
            'mappings': {
                wg: {
                    'fmc_user': m.fmc_user.name if m.fmc_user else None,
                    'fmc_user_id': m.fmc_user.id if m.fmc_user else None,
                    'realm': m.fmc_user.realm_name if m.fmc_user else None,
                    'confidence': m.match_confidence,
                    'method': m.match_method
                }
                for wg, m in self.user_mappings.items()
            },
            'unmatched': [u for u, m in self.user_mappings.items() if not m.fmc_user]
        }
