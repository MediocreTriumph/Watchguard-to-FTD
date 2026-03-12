#!/usr/bin/env python3
"""
WatchGuard Parser v5 - Service Deduplication with Port Group Creation

Key improvements over v3:
1. Services with same name but different protocols/ports are ALL preserved
2. Individual service objects get unique names: PDQ_TCP_139, PDQ_UDP_137
3. Service groups created for multi-service names: PDQ_svc_group
4. ICMP tracked separately (can't be in FMC port groups)
5. Unsupported/special protocols (GRE, ESP, HOPOPT) tracked with warnings
6. original_name field tracks WatchGuard service name for policy mapping

FMC Constraints Addressed:
- Port Object Groups can contain TCP and UDP objects mixed together
- ICMP objects CANNOT be added to port groups - tracked in icmp_members
- Protocol-only objects (GRE, ESP) handled separately - tracked in protocol_members
- Unsupported protocols generate warnings
"""

import sys
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from collections import defaultdict


# Protocol number to name mapping
PROTOCOLS = {
    "0": "HOPOPT",
    "1": "ICMP", 
    "2": "IGMP",
    "6": "TCP",
    "17": "UDP",
    "47": "GRE",
    "50": "ESP",
    "51": "AH",
    "58": "ICMPv6",
    "89": "OSPFIGP"
}

# Protocols that can be created as ProtocolPortObjects (require port)
PORT_BASED_PROTOCOLS = {"TCP", "UDP"}

# Protocols that use ICMPV4Object or ICMPV6Object
ICMP_PROTOCOLS = {"ICMP", "ICMPv6"}

# Protocols that are protocol-only (no port) - FMC has built-in support
# These can be used in rules via literal protocol number
PROTOCOL_ONLY = {"GRE", "ESP", "AH", "IGMP", "OSPFIGP"}

# Truly unsupported protocols that should generate warnings
UNSUPPORTED_PROTOCOLS = {"HOPOPT"}


def sanitize_port_for_name(port: str) -> str:
    """
    Sanitize port value for use in object names.
    Examples:
        "139" -> "139"
        "135-139" -> "135-139" 
        "80,443" -> "80_443"
    """
    if not port:
        return ""
    # Replace commas with underscores for multi-port
    return port.replace(",", "_")


def generate_service_name(original_name: str, protocol: str, port: str = None) -> str:
    """
    Generate unique FMC-compliant service object name.
    
    Examples:
        PDQ, TCP, 139 -> PDQ_TCP_139
        PDQ, UDP, 137-138 -> PDQ_UDP_137-138  
        PDQ, ICMP, None -> PDQ_ICMP
        PDQ, GRE, None -> PDQ_GRE
    """
    if port:
        sanitized_port = sanitize_port_for_name(port)
        return f"{original_name}_{protocol}_{sanitized_port}"
    else:
        return f"{original_name}_{protocol}"


def parse_watchguard_config(xml_file):
    """Parse WatchGuard XML config and return structured JSON"""
    
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    config = {
        "metadata": {
            "parsed_date": datetime.now().isoformat(),
            "source_file": xml_file,
            "parser_version": "v5"
        },
        "addresses": {
            "hosts": {},
            "networks": {},
            "ranges": {},
            "fqdns": {}
        },
        "address_groups": [],
        "interface_aliases": [],
        "services": {
            "tcp": [],
            "udp": [],
            "icmp": [],
            "protocol_only": [],  # GRE, ESP, etc.
            "other": []  # Unsupported
        },
        "service_groups": [],
        "routes": [],
        "interfaces": [],
        "policies": [],
        "nat_rules": [],
        "sdwan_actions": [],
        "app_actions": [],
        "geo_actions": []
    }
    
    # =========================================================================
    # PHASE 1: Collect all service definitions (don't deduplicate yet)
    # =========================================================================
    
    # Track services by original name for grouping
    # Key: original_name, Value: list of (protocol, port, description)
    services_by_name = defaultdict(list)
    
    for service in root.findall("./service-list/service"):
        name = ""
        description = ""
        
        for elem in service:
            if elem.tag == "name":
                name = elem.text
            elif elem.tag == "description":
                description = elem.text if elem.text else ""
            elif elem.tag == "service-item":
                for item in elem:
                    protocol = None
                    port = None
                    
                    for field in item:
                        if field.tag == "protocol":
                            protocol = PROTOCOLS.get(field.text, field.text)
                        elif field.tag == "server-port":
                            port = field.text
                    
                    if protocol and name:
                        services_by_name[name].append({
                            "protocol": protocol,
                            "port": port,
                            "description": description
                        })
    
    # =========================================================================
    # PHASE 2: Process services and create groups for duplicates
    # =========================================================================
    
    # Track which names we've seen to detect true uniqueness
    # For names with single service entry, no group needed
    # For names with multiple entries, create group
    
    for original_name, service_list in services_by_name.items():
        needs_group = len(service_list) > 1
        
        # Track members for potential group creation
        tcp_udp_members = []  # Can go in port group
        icmp_members = []      # Must be separate
        protocol_members = []  # Protocol-only (GRE, ESP)
        warnings = []
        
        for svc in service_list:
            protocol = svc["protocol"]
            port = svc["port"]
            description = svc["description"]
            
            # Generate unique name if this service name has multiple definitions
            if needs_group:
                unique_name = generate_service_name(original_name, protocol, port)
            else:
                # Single service - keep original name
                unique_name = original_name
            
            # Build service object
            service_obj = {
                "name": unique_name,
                "original_name": original_name,
                "description": f"{original_name} service ({protocol}" + (f"/{port})" if port else ")"),
            }
            if port:
                service_obj["port"] = port
            
            # Categorize by protocol type
            if protocol in PORT_BASED_PROTOCOLS:
                # TCP/UDP - can go in port groups
                if protocol == "TCP":
                    config["services"]["tcp"].append(service_obj)
                else:
                    config["services"]["udp"].append(service_obj)
                
                if needs_group:
                    tcp_udp_members.append(unique_name)
                    
            elif protocol in ICMP_PROTOCOLS:
                # ICMP/ICMPv6 - cannot go in port groups
                service_obj["icmp_version"] = "v6" if protocol == "ICMPv6" else "v4"
                config["services"]["icmp"].append(service_obj)
                
                if needs_group:
                    icmp_members.append(unique_name)
                    
            elif protocol in PROTOCOL_ONLY:
                # GRE, ESP, etc. - protocol-only, FMC has built-in support
                service_obj["protocol"] = protocol
                service_obj["protocol_number"] = {v: k for k, v in PROTOCOLS.items()}.get(protocol, "")
                config["services"]["protocol_only"].append(service_obj)
                
                if needs_group:
                    protocol_members.append(unique_name)
                    
            elif protocol in UNSUPPORTED_PROTOCOLS:
                # Truly unsupported
                service_obj["protocol"] = protocol
                config["services"]["other"].append(service_obj)
                warnings.append(f"Unsupported protocol {protocol} skipped")
                
            else:
                # Unknown protocol - treat as other
                service_obj["protocol"] = protocol
                config["services"]["other"].append(service_obj)
                warnings.append(f"Unknown protocol {protocol} - may require manual handling")
        
        # Create service group if multiple services share the name
        if needs_group:
            group = {
                "name": f"{original_name}_svc_group",
                "original_name": original_name,
                "description": f"Service group for {original_name} ({len(service_list)} original services)",
                "members": tcp_udp_members,  # TCP/UDP only - can go in FMC port group
            }
            
            # Track ICMP separately - must be added to rules individually
            if icmp_members:
                group["icmp_members"] = icmp_members
            
            # Track protocol-only separately - require special handling
            if protocol_members:
                group["protocol_members"] = protocol_members
            
            # Track any warnings
            if warnings:
                group["warnings"] = list(set(warnings))  # Dedupe warnings
            
            config["service_groups"].append(group)
    
    # =========================================================================
    # Parse Routes
    # =========================================================================
    for route in root.findall("./system-parameters/route/route-entry"):
        route_obj = {}
        for elem in route:
            if elem.tag == "dest-address":
                route_obj["destination"] = elem.text
            elif elem.tag == "mask":
                route_obj["mask"] = elem.text
            elif elem.tag == "gateway-ip":
                route_obj["gateway"] = elem.text
        if route_obj:
            config["routes"].append(route_obj)
    
    # =========================================================================
    # Parse Address Objects - using dict to deduplicate by name
    # =========================================================================
    for addr_group in root.findall("./address-group-list/address-group"):
        name = ""
        description = ""
        
        for elem in addr_group:
            if elem.tag == "name":
                name = elem.text
            elif elem.tag == "description":
                description = elem.text if elem.text else ""
            elif elem.tag == "addr-group-member":
                for member in elem:
                    host_ip = network_addr = mask = start_addr = end_addr = fqdn = None
                    
                    for field in member:
                        if field.tag == "host-ip-addr":
                            host_ip = field.text
                        elif field.tag == "ip-network-addr":
                            network_addr = field.text
                        elif field.tag == "ip-mask":
                            mask = field.text
                        elif field.tag == "start-ip-addr":
                            start_addr = field.text
                        elif field.tag == "end-ip-addr":
                            end_addr = field.text
                        elif field.tag == "domain":
                            fqdn = field.text
                    
                    # Categorize by type - store in dict to deduplicate
                    if host_ip:
                        if name not in config["addresses"]["hosts"]:
                            config["addresses"]["hosts"][name] = {
                                "name": name,
                                "description": description,
                                "ip": host_ip
                            }
                    elif network_addr and mask:
                        if name not in config["addresses"]["networks"]:
                            config["addresses"]["networks"][name] = {
                                "name": name,
                                "description": description,
                                "network": network_addr,
                                "mask": mask
                            }
                    elif start_addr and end_addr:
                        if name not in config["addresses"]["ranges"]:
                            config["addresses"]["ranges"][name] = {
                                "name": name,
                                "description": description,
                                "start": start_addr,
                                "end": end_addr
                            }
                    elif fqdn:
                        if name not in config["addresses"]["fqdns"]:
                            config["addresses"]["fqdns"][name] = {
                                "name": name,
                                "description": description,
                                "fqdn": fqdn
                            }
    
    # =========================================================================
    # Parse Aliases
    # =========================================================================
    for alias in root.findall("./alias-list/alias"):
        alias_obj = {
            "name": "",
            "description": "",
            "member_types": [],
            "member_users": [],
            "members": [],
            "alias_references": [],
            "member_interfaces": []
        }
        
        for elem in alias:
            if elem.tag == "name":
                alias_obj["name"] = elem.text
            elif elem.tag == "description":
                alias_obj["description"] = elem.text if elem.text else ""
            elif elem.tag == "alias-member-list":
                for alias_member in elem.findall("alias-member"):
                    for field in alias_member:
                        if field.tag == "type":
                            alias_obj["member_types"].append(field.text)
                        elif field.tag == "user":
                            alias_obj["member_users"].append(field.text)
                        elif field.tag == "address":
                            alias_obj["members"].append(field.text)
                        elif field.tag == "alias-name":
                            alias_obj["alias_references"].append(field.text)
                        elif field.tag == "interface":
                            alias_obj["member_interfaces"].append(field.text)
        
        # Deduplicate lists
        alias_obj["member_types"] = list(dict.fromkeys(alias_obj["member_types"]))
        alias_obj["member_users"] = list(dict.fromkeys(alias_obj["member_users"]))
        alias_obj["members"] = list(dict.fromkeys(alias_obj["members"]))
        alias_obj["alias_references"] = list(dict.fromkeys(alias_obj["alias_references"]))
        alias_obj["member_interfaces"] = list(dict.fromkeys(alias_obj["member_interfaces"]))
        
        # Special case: if only 'Any', keep just one
        if alias_obj["members"] and all(m == "Any" for m in alias_obj["members"]):
            alias_obj["members"] = ["Any"]
        
        # Separate interface aliases from address groups
        is_interface_alias = (
            len(alias_obj["member_interfaces"]) > 0 and 
            len(alias_obj["members"]) == 0 and
            len(alias_obj["alias_references"]) == 0
        ) or alias_obj["name"] in ["Any", "Firebox", "Any-External", "Any-Trusted", "Any-Optional"]
        
        if is_interface_alias:
            config["interface_aliases"].append(alias_obj)
        else:
            config["address_groups"].append(alias_obj)
    
    # =========================================================================
    # Parse Interfaces
    # =========================================================================
    for interface in root.findall("./interface-list/interface"):
        intf = {
            "name": "",
            "description": "",
            "device_name": "",
            "enabled": "",
            "node_type": "",
            "ip": "",
            "gateway": "",
            "mask": "",
            "secondary_ips": []
        }
        
        for elem in interface:
            if elem.tag == "name":
                intf["name"] = elem.text
            elif elem.tag == "description":
                intf["description"] = elem.text if elem.text else ""
            elif elem.tag == "if-item-list":
                for item in elem:
                    for physif in item:
                        for field in physif:
                            if field.tag == "if-dev-name":
                                intf["device_name"] = field.text
                            elif field.tag == "enabled":
                                intf["enabled"] = field.text
                            elif field.tag == "ip-node-type":
                                intf["node_type"] = field.text
                            elif field.tag == "ip":
                                intf["ip"] = field.text
                            elif field.tag == "default-gateway":
                                intf["gateway"] = field.text
                            elif field.tag == "netmask":
                                intf["mask"] = field.text
                            elif field.tag == "secondary-ip-list":
                                for sec_ip in field:
                                    for ip_elem in sec_ip:
                                        if ip_elem.text:
                                            intf["secondary_ips"].append(ip_elem.text)
        
        config["interfaces"].append(intf)
    
    # =========================================================================
    # Build alias lookup map for policy resolution
    # =========================================================================
    alias_map = {}
    for alias in config["address_groups"] + config["interface_aliases"]:
        alias_map[alias["name"]] = alias
    
    def resolve_alias_members(alias_name, visited=None):
        """Recursively resolve an alias to all its final address object members"""
        if visited is None:
            visited = set()
        
        if alias_name in visited:
            return []
        visited.add(alias_name)
        
        if alias_name == "Any":
            return ["Any"]
        
        if alias_name not in alias_map:
            return []
        
        alias = alias_map[alias_name]
        resolved = []
        
        resolved.extend(alias["members"])
        
        for ref in alias["alias_references"]:
            resolved.extend(resolve_alias_members(ref, visited))
        
        return resolved
    
    # =========================================================================
    # Parse Policies
    # =========================================================================
    for policy in root.findall("./abs-policy-list/abs-policy"):
        pol = {
            "name": "",
            "source_aliases": [],
            "destination_aliases": [],
            "source_members": [],
            "destination_members": [],
            "service": "",
            "enabled": "",
            "action": "",
            "nat_policy": "",
            "description": "",
            "reject_action": "",
            "tag": "",
            "schedule": "",
            "log_enabled": "",
            "route_policy": "",
            "proxy": "",
            "sdwan_action": "",
            "app_action": ""
        }
        
        for elem in policy:
            if elem.tag == "name":
                pol["name"] = elem.text
            elif elem.tag == "from-alias-list":
                for alias_ref in elem:
                    alias_name = alias_ref.text
                    pol["source_aliases"].append(alias_name)
                    resolved = resolve_alias_members(alias_name)
                    pol["source_members"].extend(resolved)
            elif elem.tag == "to-alias-list":
                for alias_ref in elem:
                    alias_name = alias_ref.text
                    pol["destination_aliases"].append(alias_name)
                    resolved = resolve_alias_members(alias_name)
                    pol["destination_members"].extend(resolved)
            elif elem.tag == "service":
                pol["service"] = elem.text
            elif elem.tag == "enabled":
                pol["enabled"] = elem.text
            elif elem.tag == "firewall":
                pol["action"] = elem.text
            elif elem.tag == "policy-nat":
                pol["nat_policy"] = elem.text
            elif elem.tag == "description":
                pol["description"] = elem.text if elem.text else ""
            elif elem.tag == "reject-action":
                pol["reject_action"] = elem.text
            elif elem.tag == "tag-list":
                pol["tag"] = ",".join([a.text for a in elem if a.text])
            elif elem.tag == "settings":
                for setting in elem:
                    if setting.tag == "schedule":
                        pol["schedule"] = setting.text
                    elif setting.tag == "log-enabled":
                        pol["log_enabled"] = setting.text
                    elif setting.tag == "policy-routing":
                        pol["route_policy"] = setting.text
                    elif setting.tag == "proxy":
                        pol["proxy"] = setting.text
                    elif setting.tag == "sdwan-action":
                        pol["sdwan_action"] = setting.text
            elif elem.tag == "app-action":
                pol["app_action"] = elem.text if elem.text else ""
        
        # Deduplicate members
        pol["source_members"] = list(dict.fromkeys(pol["source_members"]))
        pol["destination_members"] = list(dict.fromkeys(pol["destination_members"]))
        
        config["policies"].append(pol)
    
    # =========================================================================
    # Parse NAT Rules
    # =========================================================================
    for nat in root.findall("./nat-list/nat"):
        nat_rule = {
            "name": "",
            "type": "",
            "algorithm": "",
            "proxy_arp": "",
            "address_type": "",
            "port": "",
            "external_address": "",
            "interface": "",
            "internal_address": ""
        }
        
        for elem in nat:
            if elem.tag == "name":
                nat_rule["name"] = elem.text
            elif elem.tag == "type":
                nat_rule["type"] = elem.text
            elif elem.tag == "algorithm":
                nat_rule["algorithm"] = elem.text
            elif elem.tag == "proxy-arp":
                nat_rule["proxy_arp"] = elem.text
            elif elem.tag == "nat-item":
                for item in elem:
                    for field in item:
                        if field.tag == "addr-type":
                            nat_rule["address_type"] = field.text
                        elif field.tag == "port":
                            nat_rule["port"] = field.text
                        elif field.tag == "ext-addr-name":
                            nat_rule["external_address"] = field.text
                        elif field.tag == "interface":
                            nat_rule["interface"] = field.text
                        elif field.tag == "addr-name":
                            nat_rule["internal_address"] = field.text
        
        config["nat_rules"].append(nat_rule)
    
    # =========================================================================
    # Parse SDWAN Actions
    # =========================================================================
    SDWAN_ALGORITHMS = {
        "1": "Global",
        "2": "Failover (Immediate Failback)"
    }
    
    for sdwan in root.findall("./sdwan-action-list/sdwan-action"):
        action = {
            "name": "",
            "description": "",
            "algorithm": "",
            "algorithm_description": "",
            "interfaces": [],
            "primary_interface": "",
            "secondary_interface": "",
            "failback_grace_period": ""
        }
        
        for elem in sdwan:
            if elem.tag == "name":
                action["name"] = elem.text
            elif elem.tag == "description":
                action["description"] = elem.text if elem.text else ""
            elif elem.tag == "algorithm":
                action["algorithm"] = elem.text
                action["algorithm_description"] = SDWAN_ALGORITHMS.get(elem.text, f"Unknown ({elem.text})")
            elif elem.tag == "failback-grace-period":
                action["failback_grace_period"] = elem.text
            elif elem.tag == "if-list":
                for if_name in elem.findall("if-name"):
                    action["interfaces"].append(if_name.text)
                if len(action["interfaces"]) >= 1:
                    action["primary_interface"] = action["interfaces"][0]
                if len(action["interfaces"]) >= 2:
                    action["secondary_interface"] = action["interfaces"][1]
        
        config["sdwan_actions"].append(action)
    
    # =========================================================================
    # Parse Application Control
    # =========================================================================
    for app in root.findall("./app-action-list/app-action"):
        app_action = {
            "name": "",
            "description": "",
            "allowed_apps": [],
            "blocked_apps": [],
            "fallthrough_action": ""
        }
        
        for elem in app:
            if elem.tag == "name":
                app_action["name"] = elem.text
            elif elem.tag == "description":
                app_action["description"] = elem.text if elem.text else ""
            elif elem.tag == "fallthrough":
                app_action["fallthrough_action"] = elem.text
            elif elem.tag == "allow-list":
                for app_elem in elem.findall("app"):
                    for field in app_elem:
                        if field.tag == "name":
                            app_action["allowed_apps"].append(field.text)
            elif elem.tag == "block-list":
                for app_elem in elem.findall("app"):
                    for field in app_elem:
                        if field.tag == "name":
                            app_action["blocked_apps"].append(field.text)
        
        config["app_actions"].append(app_action)
    
    # =========================================================================
    # Parse Geo Blocking
    # =========================================================================
    for geo in root.findall(".//geo-action-list/geo-action"):
        geo_action = {
            "name": "",
            "description": "",
            "blocked_countries": []
        }
        
        for elem in geo:
            if elem.tag == "name":
                geo_action["name"] = elem.text
            elif elem.tag == "description":
                geo_action["description"] = elem.text if elem.text else ""
            elif elem.tag == "geo-list":
                for geo_elem in elem.findall("geo"):
                    for field in geo_elem:
                        if field.tag == "country":
                            geo_action["blocked_countries"].append(field.text)
        
        config["geo_actions"].append(geo_action)
    
    # =========================================================================
    # Convert address dicts to lists for final output
    # =========================================================================
    config["addresses"]["hosts"] = list(config["addresses"]["hosts"].values())
    config["addresses"]["networks"] = list(config["addresses"]["networks"].values())
    config["addresses"]["ranges"] = list(config["addresses"]["ranges"].values())
    config["addresses"]["fqdns"] = list(config["addresses"]["fqdns"].values())
    
    return config


def analyze_group_dependencies(config):
    """Analyze address group dependencies to determine creation order"""
    
    dependencies = {}
    for group in config["address_groups"]:
        deps = set()
        for ref in group["alias_references"]:
            if any(g["name"] == ref for g in config["address_groups"]):
                deps.add(ref)
        dependencies[group["name"]] = deps
    
    no_deps = [name for name, deps in dependencies.items() if len(deps) == 0]
    with_deps = [name for name, deps in dependencies.items() if len(deps) > 0]
    
    def get_depth(name, visited=None):
        if visited is None:
            visited = set()
        if name in visited:
            return 0
        visited.add(name)
        
        if name not in dependencies or len(dependencies[name]) == 0:
            return 0
        
        return 1 + max(get_depth(dep, visited.copy()) for dep in dependencies[name])
    
    max_depth = max([get_depth(name) for name in dependencies.keys()]) if dependencies else 0
    
    return {
        "total_groups": len(config["address_groups"]),
        "groups_with_no_dependencies": len(no_deps),
        "groups_with_dependencies": len(with_deps),
        "max_nesting_depth": max_depth,
        "dependencies": dependencies
    }


def analyze_service_groups(config):
    """Analyze service group statistics"""
    
    groups = config["service_groups"]
    
    stats = {
        "total_groups": len(groups),
        "groups_with_icmp": sum(1 for g in groups if g.get("icmp_members")),
        "groups_with_protocol_only": sum(1 for g in groups if g.get("protocol_members")),
        "groups_with_warnings": sum(1 for g in groups if g.get("warnings")),
        "total_tcp_udp_members": sum(len(g.get("members", [])) for g in groups),
        "total_icmp_members": sum(len(g.get("icmp_members", [])) for g in groups),
        "total_protocol_members": sum(len(g.get("protocol_members", [])) for g in groups),
    }
    
    # Collect all warnings
    all_warnings = []
    for g in groups:
        if g.get("warnings"):
            for w in g["warnings"]:
                all_warnings.append(f"{g['name']}: {w}")
    stats["warnings_detail"] = all_warnings
    
    return stats


def validate_references(config):
    """Validate that group members reference existing objects"""
    
    all_addresses = set()
    for addr_type in ["hosts", "networks", "ranges", "fqdns"]:
        for obj in config["addresses"][addr_type]:
            all_addresses.add(obj["name"])
    
    for alias in config["interface_aliases"]:
        all_addresses.add(alias["name"])
    
    all_group_names = set()
    for group in config["address_groups"]:
        all_group_names.add(group["name"])
    
    all_services = set()
    for svc_type in ["tcp", "udp", "icmp", "protocol_only", "other"]:
        for obj in config["services"][svc_type]:
            all_services.add(obj["name"])
            # Also track by original_name for policy lookup
            if "original_name" in obj:
                all_services.add(obj["original_name"])
    
    # Add service group names
    for group in config["service_groups"]:
        all_services.add(group["name"])
        all_services.add(group["original_name"])
    
    issues = {
        "broken_address_references": [],
        "broken_alias_references": [],
        "interface_aliases_count": len(config["interface_aliases"])
    }
    
    for group in config["address_groups"]:
        for member in group["members"]:
            if member != "Any" and member not in all_addresses and member not in all_group_names:
                issues["broken_address_references"].append({
                    "group": group["name"],
                    "missing_member": member
                })
        
        for ref in group["alias_references"]:
            if ref not in all_group_names and ref not in [a["name"] for a in config["interface_aliases"]]:
                issues["broken_alias_references"].append({
                    "group": group["name"],
                    "missing_alias": ref
                })
    
    return issues


def build_service_lookup(config):
    """
    Build lookup structure for service resolution.
    
    Returns dict with:
    - by_original_name: Maps original WG name -> service group OR individual service
    - by_unique_name: Maps unique FMC name -> service object
    """
    lookup = {
        "by_original_name": {},
        "by_unique_name": {},
        "service_groups": {}
    }
    
    # First, index all service groups by original name
    for group in config["service_groups"]:
        lookup["by_original_name"][group["original_name"]] = {
            "type": "group",
            "group": group
        }
        lookup["service_groups"][group["name"]] = group
    
    # Then, index individual services
    for svc_type in ["tcp", "udp", "icmp", "protocol_only", "other"]:
        for svc in config["services"][svc_type]:
            # Index by unique name
            lookup["by_unique_name"][svc["name"]] = {
                "type": svc_type,
                "service": svc
            }
            
            # For original names NOT in a group, also index by original name
            original = svc.get("original_name", svc["name"])
            if original not in lookup["by_original_name"]:
                lookup["by_original_name"][original] = {
                    "type": svc_type,
                    "service": svc
                }
    
    return lookup


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ./watchparse-json-v5.py <config.xml>")
        sys.exit(1)
    
    xml_file = sys.argv[1]
    
    # Parse config
    config = parse_watchguard_config(xml_file)
    
    # Analyze dependencies
    dep_analysis = analyze_group_dependencies(config)
    
    # Analyze service groups
    svc_analysis = analyze_service_groups(config)
    
    # Validate references
    issues = validate_references(config)
    
    # Build service lookup
    svc_lookup = build_service_lookup(config)
    
    # Generate output filename
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M')
    json_file = f"watchguard_config_v5_{timestamp}.json"
    
    # Write JSON output
    with open(json_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Print summary
    print(f"✓ Parsed configuration from {xml_file}")
    print(f"✓ Output written to {json_file}")
    print("\n" + "="*60)
    print("ADDRESS OBJECTS")
    print("="*60)
    print(f"Hosts:           {len(config['addresses']['hosts'])}")
    print(f"Networks:        {len(config['addresses']['networks'])}")
    print(f"Ranges:          {len(config['addresses']['ranges'])}")
    print(f"FQDNs:           {len(config['addresses']['fqdns'])}")
    print(f"Address Groups:  {len(config['address_groups'])}")
    print(f"  - No dependencies:   {dep_analysis['groups_with_no_dependencies']}")
    print(f"  - With dependencies: {dep_analysis['groups_with_dependencies']}")
    print(f"  - Max nesting depth: {dep_analysis['max_nesting_depth']}")
    print(f"Interface Aliases: {len(config['interface_aliases'])}")
    
    print("\n" + "="*60)
    print("SERVICE OBJECTS (v5 - Deduplicated)")
    print("="*60)
    print(f"TCP Services:      {len(config['services']['tcp'])}")
    print(f"UDP Services:      {len(config['services']['udp'])}")
    print(f"ICMP Services:     {len(config['services']['icmp'])}")
    print(f"Protocol-Only:     {len(config['services']['protocol_only'])} (GRE, ESP, etc.)")
    print(f"Other/Unsupported: {len(config['services']['other'])}")
    
    print(f"\nService Groups:    {svc_analysis['total_groups']}")
    if svc_analysis['total_groups'] > 0:
        print(f"  - With ICMP members:     {svc_analysis['groups_with_icmp']}")
        print(f"  - With protocol-only:    {svc_analysis['groups_with_protocol_only']}")
        print(f"  - With warnings:         {svc_analysis['groups_with_warnings']}")
        print(f"  - Total TCP/UDP members: {svc_analysis['total_tcp_udp_members']}")
        print(f"  - Total ICMP members:    {svc_analysis['total_icmp_members']}")
        print(f"  - Total protocol-only:   {svc_analysis['total_protocol_members']}")
    
    if svc_analysis['warnings_detail']:
        print(f"\n⚠ Service Warnings:")
        for w in svc_analysis['warnings_detail'][:10]:
            print(f"  - {w}")
        if len(svc_analysis['warnings_detail']) > 10:
            print(f"  ... and {len(svc_analysis['warnings_detail']) - 10} more")
    
    print("\n" + "="*60)
    print("POLICIES & OTHER")
    print("="*60)
    print(f"Policies:        {len(config['policies'])}")
    print(f"NAT Rules:       {len(config['nat_rules'])}")
    print(f"Interfaces:      {len(config['interfaces'])}")
    
    # Report validation issues
    if issues["broken_address_references"]:
        print(f"\n⚠ Warning: {len(issues['broken_address_references'])} broken address references")
        for issue in issues["broken_address_references"][:3]:
            print(f"  - Group '{issue['group']}' → missing '{issue['missing_member']}'")
        if len(issues["broken_address_references"]) > 3:
            print(f"  ... and {len(issues['broken_address_references']) - 3} more")
    
    if issues["broken_alias_references"]:
        print(f"\n⚠ Warning: {len(issues['broken_alias_references'])} broken alias references")
        for issue in issues["broken_alias_references"][:3]:
            print(f"  - Group '{issue['group']}' → missing alias '{issue['missing_alias']}'")
        if len(issues["broken_alias_references"]) > 3:
            print(f"  ... and {len(issues['broken_alias_references']) - 3} more")
    
    print(f"\nℹ Separated {issues['interface_aliases_count']} interface aliases from address groups")
    
    # Show example service groups
    if config["service_groups"]:
        print("\n" + "="*60)
        print("EXAMPLE SERVICE GROUPS")
        print("="*60)
        for group in config["service_groups"][:3]:
            print(f"\n{group['name']} (original: {group['original_name']})")
            print(f"  TCP/UDP members: {group['members'][:5]}" + ("..." if len(group['members']) > 5 else ""))
            if group.get("icmp_members"):
                print(f"  ICMP members:    {group['icmp_members']}")
            if group.get("protocol_members"):
                print(f"  Protocol-only:   {group['protocol_members']}")
            if group.get("warnings"):
                print(f"  Warnings:        {group['warnings']}")
