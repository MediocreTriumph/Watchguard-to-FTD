"""
Service mapping from WatchGuard to FMC canonical objects.
"""

from typing import Dict, Optional
from models import WatchGuardService, FMCObject, FMCObjects
from fmc.canonical import CanonicalPortMapper


class ServiceMapper:
    """Maps WatchGuard services to FMC canonical objects."""
    
    def __init__(self, fmc_objects: FMCObjects, canonical_mapper: CanonicalPortMapper):
        self.fmc_objects = fmc_objects
        self.canonical_mapper = canonical_mapper
        self.service_mappings: Dict[str, FMCObject] = {}
        self.unmapped_services: Dict[str, WatchGuardService] = {}
    
    def map_services(self, wg_services: list) -> Dict[str, FMCObject]:
        """
        Map all WatchGuard services to canonical FMC objects.
        
        This is where the magic happens:
        - "Windows_Update" (TCP/80) -> HTTP
        - "AWS-Standard" (TCP/80) -> HTTP  
        - "WG-Cloud-Managed-WiFi.1" (TCP/80) -> HTTP
        
        All resolve to the same canonical object.
        """
        print("\n" + "="*60)
        print("MAPPING SERVICES TO CANONICAL OBJECTS")
        print("="*60)
        
        mapped_count = 0
        unmapped_count = 0
        
        for wg_service in wg_services:
            if not wg_service.port:
                # ICMP or other protocol without port
                unmapped_count += 1
                self.unmapped_services[wg_service.name] = wg_service
                continue
            
            # Resolve to canonical FMC object
            canonical = self.canonical_mapper.resolve_service(
                wg_service.name,
                wg_service.protocol,
                wg_service.port
            )
            
            if canonical:
                self.service_mappings[wg_service.name] = canonical
                mapped_count += 1
            else:
                self.unmapped_services[wg_service.name] = wg_service
                unmapped_count += 1
        
        print(f"\nResults:")
        print(f"  Mapped to canonical:  {mapped_count}")
        print(f"  Unmapped:             {unmapped_count}")
        
        # Show examples of deduplication
        self._show_deduplication_examples(wg_services)
        
        return self.service_mappings
    
    def _show_deduplication_examples(self, wg_services: list):
        """Show examples of services that map to the same canonical object."""
        print("\nDeduplication Examples:")
        print("-"*60)
        
        # Group WG services by their canonical mapping
        canonical_to_wg: Dict[str, list] = {}
        
        for wg_service in wg_services:
            if wg_service.name in self.service_mappings:
                canonical = self.service_mappings[wg_service.name]
                canonical_name = canonical.name
                
                if canonical_name not in canonical_to_wg:
                    canonical_to_wg[canonical_name] = []
                canonical_to_wg[canonical_name].append(wg_service.name)
        
        # Show top 5 deduplications
        duplications = [(name, services) for name, services in canonical_to_wg.items() if len(services) > 1]
        duplications.sort(key=lambda x: len(x[1]), reverse=True)
        
        for canonical_name, wg_services_list in duplications[:5]:
            print(f"\n{canonical_name} (canonical):")
            for wg_name in wg_services_list[:5]:
                print(f"  ← {wg_name}")
            if len(wg_services_list) > 5:
                print(f"  ... and {len(wg_services_list) - 5} more")
    
    def get_mapping(self, wg_service_name: str) -> Optional[FMCObject]:
        """Get FMC canonical object for a WatchGuard service name."""
        return self.service_mappings.get(wg_service_name)
    
    def needs_creation(self, wg_service_name: str) -> bool:
        """Check if a service needs to be created (not mapped to existing)."""
        return wg_service_name in self.unmapped_services
    
    def get_statistics(self) -> Dict[str, int]:
        """Get mapping statistics."""
        # Count unique canonical objects used
        unique_canonical = set(obj.id for obj in self.service_mappings.values())
        
        # Count how many WG services map to each canonical
        canonical_usage: Dict[str, int] = {}
        for canonical in self.service_mappings.values():
            canonical_usage[canonical.id] = canonical_usage.get(canonical.id, 0) + 1
        
        duplications = sum(1 for count in canonical_usage.values() if count > 1)
        
        return {
            "total_wg_services": len(self.service_mappings) + len(self.unmapped_services),
            "mapped_to_canonical": len(self.service_mappings),
            "unmapped": len(self.unmapped_services),
            "unique_canonical_objects": len(unique_canonical),
            "services_deduplicated": duplications
        }
