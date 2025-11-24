"""
Discovery of existing FMC objects.
"""

from typing import Dict, List
from models import FMCObject, FMCObjects
from .client import FMCClient


class FMCDiscovery:
    """Discover existing FMC objects."""
    
    def __init__(self, client: FMCClient):
        self.client = client
    
    def discover_all(self) -> FMCObjects:
        """Discover all relevant FMC objects."""
        print("\n" + "="*60)
        print("DISCOVERING FMC OBJECTS")
        print("="*60)
        
        fmc_objects = FMCObjects()
        
        # Discover network objects
        print("\nDiscovering network objects...")
        fmc_objects.hosts = self._discover_hosts()
        fmc_objects.networks = self._discover_networks()
        fmc_objects.ranges = self._discover_ranges()
        fmc_objects.fqdns = self._discover_fqdns()
        fmc_objects.network_groups = self._discover_network_groups()
        
        # Discover service objects
        print("\nDiscovering service objects...")
        fmc_objects.port_objects = self._discover_port_objects()
        fmc_objects.port_groups = self._discover_port_groups()
        fmc_objects.icmp_objects = self._discover_icmp_objects()
        
        # Discover URL objects
        print("\nDiscovering URL objects...")
        fmc_objects.url_objects = self._discover_url_objects()
        
        # Discover applications
        print("\nDiscovering applications...")
        fmc_objects.applications = self._discover_applications()
        
        self._print_summary(fmc_objects)
        
        return fmc_objects
    
    def _discover_hosts(self) -> Dict[str, FMCObject]:
        """Discover host objects."""
        objects = {}
        items = self.client.get_objects("hosts")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="Host"
            )
            objects[item['name']] = obj
        
        print(f"  Hosts: {len(objects)}")
        return objects
    
    def _discover_networks(self) -> Dict[str, FMCObject]:
        """Discover network objects."""
        objects = {}
        items = self.client.get_objects("networks")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="Network"
            )
            objects[item['name']] = obj
        
        print(f"  Networks: {len(objects)}")
        return objects
    
    def _discover_ranges(self) -> Dict[str, FMCObject]:
        """Discover range objects."""
        objects = {}
        items = self.client.get_objects("ranges")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="Range"
            )
            objects[item['name']] = obj
        
        print(f"  Ranges: {len(objects)}")
        return objects
    
    def _discover_fqdns(self) -> Dict[str, FMCObject]:
        """Discover FQDN objects."""
        objects = {}
        items = self.client.get_objects("fqdns")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="FQDN"
            )
            objects[item['name']] = obj
        
        print(f"  FQDNs: {len(objects)}")
        return objects
    
    def _discover_network_groups(self) -> Dict[str, FMCObject]:
        """Discover network group objects."""
        objects = {}
        items = self.client.get_objects("networkgroups")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="NetworkGroup"
            )
            objects[item['name']] = obj
        
        print(f"  Network Groups: {len(objects)}")
        return objects
    
    def _discover_port_objects(self) -> Dict[str, FMCObject]:
        """Discover protocol port objects."""
        objects = {}
        items = self.client.get_objects("protocolportobjects")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="ProtocolPortObject",
                protocol=item.get('protocol'),
                port=item.get('port'),
                is_builtin=item.get('overridable', False) == False
            )
            objects[item['name']] = obj
        
        print(f"  Port Objects: {len(objects)}")
        return objects
    
    def _discover_port_groups(self) -> Dict[str, FMCObject]:
        """Discover port group objects."""
        objects = {}
        items = self.client.get_objects("portobjectgroups")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="PortObjectGroup"
            )
            objects[item['name']] = obj
        
        print(f"  Port Groups: {len(objects)}")
        return objects
    
    def _discover_icmp_objects(self) -> Dict[str, FMCObject]:
        """Discover ICMP objects."""
        objects = {}
        items = self.client.get_objects("icmpv4objects")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="ICMPV4Object",
                is_builtin=item.get('overridable', False) == False
            )
            objects[item['name']] = obj
        
        print(f"  ICMP Objects: {len(objects)}")
        return objects
    
    def _discover_url_objects(self) -> Dict[str, FMCObject]:
        """Discover URL objects."""
        objects = {}
        items = self.client.get_objects("urls")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="Url"
            )
            objects[item['name']] = obj
        
        print(f"  URL Objects: {len(objects)}")
        return objects
    
    def _discover_applications(self) -> Dict[str, FMCObject]:
        """Discover application objects."""
        objects = {}
        items = self.client.get_objects("applications")
        
        for item in items:
            obj = FMCObject(
                id=item['id'],
                name=item['name'],
                type="Application",
                category=item.get('category', 'Unknown')
            )
            objects[item['name']] = obj
            # Also index by lowercase for case-insensitive lookup
            objects[item['name'].lower()] = obj
        
        print(f"  Applications: {len(items)}")
        return objects
    
    def _print_summary(self, fmc_objects: FMCObjects):
        """Print discovery summary."""
        print("\n" + "="*60)
        print("DISCOVERY COMPLETE")
        print("="*60)
        print(f"\nNetwork Objects:")
        print(f"  Hosts:          {len(fmc_objects.hosts)}")
        print(f"  Networks:       {len(fmc_objects.networks)}")
        print(f"  Ranges:         {len(fmc_objects.ranges)}")
        print(f"  FQDNs:          {len(fmc_objects.fqdns)}")
        print(f"  Groups:         {len(fmc_objects.network_groups)}")
        
        print(f"\nService Objects:")
        print(f"  Port Objects:   {len(fmc_objects.port_objects)}")
        print(f"  Port Groups:    {len(fmc_objects.port_groups)}")
        print(f"  ICMP Objects:   {len(fmc_objects.icmp_objects)}")
        
        print(f"\nOther Objects:")
        print(f"  URL Objects:    {len(fmc_objects.url_objects)}")
        print(f"  Applications:   {len(fmc_objects.applications) // 2}")  # Divided by 2 due to lowercase indexing
