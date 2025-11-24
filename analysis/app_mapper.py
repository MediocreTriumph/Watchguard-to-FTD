"""
Improved application matching with domain-specific knowledge.

Fixes the fuzzy matching problems like:
- Adobe.com -> Audible.com (WRONG)
- Apple Safari -> Apple Mail (WRONG)
- Norton -> Notion (WRONG)
"""

import re
from typing import Dict, Optional, List, Tuple
from difflib import SequenceMatcher
from models import FMCObject, FMCObjects


class ApplicationMapper:
    """Maps WatchGuard applications to FMC applications with smart matching."""
    
    def __init__(self, fmc_objects: FMCObjects, confidence_threshold: float = 0.85):
        self.fmc_objects = fmc_objects
        self.confidence_threshold = confidence_threshold
        self.app_mappings: Dict[str, FMCObject] = {}
        self.unmapped_apps: List[str] = []
    
    def map_applications(self, wg_app_names: List[str]) -> Dict[str, FMCObject]:
        """Map WatchGuard application names to FMC applications."""
        print("\n" + "="*60)
        print("MAPPING APPLICATIONS")
        print("="*60)
        
        exact_matches = 0
        fuzzy_matches = 0
        no_matches = 0
        
        for wg_app in wg_app_names:
            mapping = self._map_single_application(wg_app)
            
            if mapping:
                self.app_mappings[wg_app] = mapping['object']
                if mapping['match_type'] == 'exact':
                    exact_matches += 1
                else:
                    fuzzy_matches += 1
            else:
                self.unmapped_apps.append(wg_app)
                no_matches += 1
        
        print(f"\nResults:")
        print(f"  Exact matches:  {exact_matches}")
        print(f"  Fuzzy matches:  {fuzzy_matches}")
        print(f"  No matches:     {no_matches}")
        
        if fuzzy_matches > 0:
            self._show_fuzzy_examples()
        
        return self.app_mappings
    
    def _map_single_application(self, wg_app: str) -> Optional[Dict]:
        """Map a single application with smart matching."""
        # 1. Try exact match (case-insensitive)
        exact = self._exact_match(wg_app)
        if exact:
            return {
                'object': exact,
                'match_type': 'exact',
                'confidence': 1.0
            }
        
        # 2. Try fuzzy match with domain filtering
        fuzzy = self._fuzzy_match_with_domain(wg_app)
        if fuzzy and fuzzy['confidence'] >= self.confidence_threshold:
            return fuzzy
        
        return None
    
    def _exact_match(self, wg_app: str) -> Optional[FMCObject]:
        """Try exact match (case-insensitive)."""
        return self.fmc_objects.applications.get(wg_app.lower())
    
    def _fuzzy_match_with_domain(self, wg_app: str) -> Optional[Dict]:
        """
        Fuzzy match with domain-specific filtering.
        
        Key improvement: Only match within the same domain.
        - "Adobe.com" only matches apps containing "adobe"
        - "Apple Safari" only matches apps containing "apple"
        """
        wg_normalized = self._normalize_app_name(wg_app)
        wg_words = set(wg_normalized.split())
        
        # Extract domain keywords (important words in the name)
        domain_keywords = self._extract_domain_keywords(wg_normalized)
        
        if not domain_keywords:
            # No clear domain - use normal fuzzy matching
            return self._simple_fuzzy_match(wg_app, wg_normalized)
        
        # Filter candidates to only those containing domain keywords
        candidates = []
        for app_name, app_obj in self.fmc_objects.applications.items():
            if app_name == app_name.lower():  # Skip lowercase duplicates
                continue
            
            fmc_normalized = self._normalize_app_name(app_name)
            
            # Check if candidate contains any domain keyword
            if any(keyword in fmc_normalized for keyword in domain_keywords):
                candidates.append((app_name, app_obj, fmc_normalized))
        
        if not candidates:
            return None
        
        # Find best match among domain-filtered candidates
        best_match = None
        best_score = 0
        
        for app_name, app_obj, fmc_normalized in candidates:
            score = self._calculate_similarity(wg_normalized, fmc_normalized, wg_words)
            
            if score > best_score:
                best_score = score
                best_match = {
                    'object': app_obj,
                    'match_type': 'fuzzy',
                    'confidence': score
                }
        
        return best_match
    
    def _simple_fuzzy_match(self, wg_app: str, wg_normalized: str) -> Optional[Dict]:
        """Simple fuzzy matching without domain filtering."""
        wg_words = set(wg_normalized.split())
        
        best_match = None
        best_score = 0
        
        for app_name, app_obj in self.fmc_objects.applications.items():
            if app_name == app_name.lower():  # Skip lowercase duplicates
                continue
            
            fmc_normalized = self._normalize_app_name(app_name)
            score = self._calculate_similarity(wg_normalized, fmc_normalized, wg_words)
            
            if score > best_score:
                best_score = score
                best_match = {
                    'object': app_obj,
                    'match_type': 'fuzzy',
                    'confidence': score
                }
        
        return best_match
    
    def _normalize_app_name(self, name: str) -> str:
        """Normalize application name for comparison."""
        # Convert to lowercase
        normalized = name.lower()
        
        # Remove common suffixes
        normalized = re.sub(r'\s+(protocol|service|app|application)s?$', '', normalized)
        
        # Remove parenthetical content
        normalized = re.sub(r'\([^)]*\)', '', normalized)
        
        # Remove special characters but keep spaces
        normalized = re.sub(r'[^\w\s]', ' ', normalized)
        
        # Remove extra whitespace
        normalized = ' '.join(normalized.split())
        
        return normalized.strip()
    
    def _extract_domain_keywords(self, normalized_name: str) -> List[str]:
        """
        Extract important domain keywords from app name.
        
        Examples:
        - "adobe com" -> ["adobe"]
        - "apple safari" -> ["apple", "safari"]
        - "microsoft intune" -> ["microsoft", "intune"]
        """
        words = normalized_name.split()
        
        # Remove generic words
        generic_words = {
            'com', 'net', 'org', 'www', 'app', 'apps', 'service', 'services',
            'protocol', 'client', 'server', 'web', 'online', 'cloud'
        }
        
        keywords = [w for w in words if w not in generic_words and len(w) > 2]
        
        return keywords
    
    def _calculate_similarity(self, str1: str, str2: str, words1: set) -> float:
        """Calculate similarity score between two strings."""
        # String similarity
        string_sim = SequenceMatcher(None, str1, str2).ratio()
        
        # Word overlap bonus
        words2 = set(str2.split())
        if words1:
            word_overlap = len(words1 & words2) / len(words1)
        else:
            word_overlap = 0
        
        # Combined score (70% string similarity, 30% word overlap)
        score = (string_sim * 0.7) + (word_overlap * 0.3)
        
        return score
    
    def _show_fuzzy_examples(self):
        """Show examples of fuzzy matches for review."""
        print("\nFuzzy Match Examples (for review):")
        print("-"*60)
        
        fuzzy_mappings = [
            (wg_name, obj) for wg_name, obj in self.app_mappings.items()
        ]
        
        # Show first 10 fuzzy matches
        for i, (wg_name, fmc_obj) in enumerate(fuzzy_mappings[:10], 1):
            print(f"{i}. {wg_name}")
            print(f"   → {fmc_obj.name}")
    
    def get_mapping(self, wg_app_name: str) -> Optional[FMCObject]:
        """Get FMC application object for WatchGuard app name."""
        return self.app_mappings.get(wg_app_name)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get mapping statistics."""
        return {
            "total_wg_apps": len(self.app_mappings) + len(self.unmapped_apps),
            "mapped": len(self.app_mappings),
            "unmapped": len(self.unmapped_apps)
        }
