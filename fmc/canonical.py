"""
Canonical port mapping using IANA well-known ports.

This module maps protocol+port combinations to their canonical/well-known names,
preferring FMC built-in objects when available.
"""

from typing import Dict, Optional
from models import FMCObject, FMCObjects


# IANA Well-Known Ports (0-1023) and Common Registered Ports
IANA_WELL_KNOWN_PORTS = {
    # Format: (protocol, port) -> canonical_name
    ("TCP", "20"): "FTP-DATA",
    ("TCP", "21"): "FTP",
    ("TCP", "22"): "SSH",
    ("TCP", "23"): "TELNET",
    ("TCP", "25"): "SMTP",
    ("TCP", "53"): "DNS",
    ("UDP", "53"): "DNS",
    ("UDP", "67"): "DHCP-Server",
    ("UDP", "68"): "DHCP-Client",
    ("UDP", "69"): "TFTP",
    ("TCP", "80"): "HTTP",
    ("TCP", "88"): "Kerberos",
    ("UDP", "88"): "Kerberos",
    ("TCP", "110"): "POP3",
    ("TCP", "123"): "NTP",
    ("UDP", "123"): "NTP",
    ("TCP", "135"): "MSRPC",
    ("UDP", "137"): "NetBIOS-NS",
    ("UDP", "138"): "NetBIOS-DGM",
    ("TCP", "139"): "NetBIOS-SSN",
    ("TCP", "143"): "IMAP",
    ("UDP", "161"): "SNMP",
    ("UDP", "162"): "SNMP-Trap",
    ("TCP", "179"): "BGP",
    ("TCP", "389"): "LDAP",
    ("TCP", "443"): "HTTPS",
    ("TCP", "445"): "SMB",
    ("UDP", "445"): "SMB",
    ("TCP", "465"): "SMTPS",
    ("UDP", "514"): "SYSLOG",
    ("TCP", "515"): "LPR",
    ("UDP", "520"): "RIP",
    ("TCP", "587"): "SMTP-Submission",
    ("TCP", "636"): "LDAPS",
    ("TCP", "993"): "IMAPS",
    ("TCP", "995"): "POP3S",
    
    # Common Registered Ports (1024-49151)
    ("UDP", "1194"): "OpenVPN",
    ("TCP", "1433"): "MSSQL",
    ("UDP", "1433"): "MSSQL",
    ("TCP", "1434"): "MSSQL-Monitor",
    ("UDP", "1434"): "MSSQL-Monitor",
    ("TCP", "1521"): "Oracle",
    ("UDP", "1701"): "L2TP",
    ("TCP", "1723"): "PPTP",
    ("UDP", "1812"): "RADIUS",
    ("UDP", "1813"): "RADIUS-Acct",
    ("TCP", "2049"): "NFS",
    ("UDP", "2049"): "NFS",
    ("TCP", "3268"): "LDAP-GC",
    ("TCP", "3269"): "LDAP-GC-SSL",
    ("TCP", "3306"): "MySQL",
    ("TCP", "3389"): "RDP",
    ("TCP", "5060"): "SIP",
    ("UDP", "5060"): "SIP",
    ("TCP", "5061"): "SIP-TLS",
    ("UDP", "5061"): "SIP-TLS",
    ("TCP", "5432"): "PostgreSQL",
    ("UDP", "5500"): "VNC",
    ("TCP", "5900"): "VNC",
    ("TCP", "5985"): "WinRM-HTTP",
    ("TCP", "5986"): "WinRM-HTTPS",
    ("TCP", "6379"): "Redis",
    ("TCP", "8080"): "HTTP-Alt",
    ("TCP", "8443"): "HTTPS-Alt",
    ("TCP", "27017"): "MongoDB",
}


class CanonicalPortMapper:
    """Maps services to canonical FMC objects."""
    
    def __init__(self, fmc_objects: FMCObjects):
        self.fmc_objects = fmc_objects
        self.canonical_map: Dict[str, FMCObject] = {}
        self._build_canonical_map()
    
    def _build_canonical_map(self):
        """Build canonical mapping from FMC objects."""
        print("\nBuilding canonical port mappings...")
        
        # Group FMC port objects by protocol+port
        port_groups: Dict[str, list] = {}
        
        for name, obj in self.fmc_objects.port_objects.items():
            if obj.protocol and obj.port:
                key = f"{obj.protocol}_{obj.port}"
                if key not in port_groups:
                    port_groups[key] = []
                port_groups[key].append(obj)
        
        # For each protocol+port, select the canonical object
        for key, objects in port_groups.items():
            protocol, port = key.split('_', 1)
            
            # Check if there's an IANA well-known name
            iana_name = IANA_WELL_KNOWN_PORTS.get((protocol, port))
            
            if iana_name:
                # Find the object with this name (case-insensitive)
                canonical = None
                for obj in objects:
                    if obj.name.upper() == iana_name.upper():
                        canonical = obj
                        break
                
                if canonical:
                    self.canonical_map[key] = canonical
                    continue
            
            # No IANA name or object not found - use shortest name
            # Prefer built-in objects if available
            builtin_objects = [o for o in objects if o.is_builtin]
            
            if builtin_objects:
                canonical = min(builtin_objects, key=lambda x: len(x.name))
            else:
                canonical = min(objects, key=lambda x: len(x.name))
            
            self.canonical_map[key] = canonical
        
        print(f"  Mapped {len(self.canonical_map)} unique protocol+port combinations")
        print(f"  Using {sum(1 for o in self.canonical_map.values() if o.is_builtin)} built-in objects")
    
    def get_canonical(self, protocol: str, port: str) -> Optional[FMCObject]:
        """Get canonical FMC object for a protocol+port."""
        key = f"{protocol}_{port}"
        return self.canonical_map.get(key)
    
    def get_canonical_name(self, protocol: str, port: str) -> str:
        """Get canonical name for a protocol+port."""
        canonical = self.get_canonical(protocol, port)
        if canonical:
            return canonical.name
        
        # Fallback to IANA name if no FMC object exists
        iana_name = IANA_WELL_KNOWN_PORTS.get((protocol, port))
        if iana_name:
            return iana_name
        
        # Last resort - generate name
        return f"{protocol}_{port}"
    
    def resolve_service(self, wg_service_name: str, protocol: str, port: str) -> Optional[FMCObject]:
        """
        Resolve a WatchGuard service name to canonical FMC object.
        
        This is the critical function that maps:
        - "Windows_Update" (TCP/80) -> HTTP object
        - "AWS-Standard" (TCP/80) -> HTTP object
        - "WG-Cloud-Managed-WiFi.1" (TCP/80) -> HTTP object
        
        All map to the same canonical HTTP object.
        """
        # First, try exact name match (if it's already canonical)
        if wg_service_name in self.fmc_objects.port_objects:
            obj = self.fmc_objects.port_objects[wg_service_name]
            # Verify it matches the protocol/port
            if obj.protocol == protocol and obj.port == port:
                return obj
        
        # Use canonical mapping based on protocol+port
        return self.get_canonical(protocol, port)
    
    def get_statistics(self) -> Dict[str, int]:
        """Get statistics about canonical mappings."""
        return {
            "total_unique_ports": len(self.canonical_map),
            "builtin_objects": sum(1 for o in self.canonical_map.values() if o.is_builtin),
            "custom_objects": sum(1 for o in self.canonical_map.values() if not o.is_builtin),
        }
