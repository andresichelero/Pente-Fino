from __future__ import annotations

import ipaddress
import socket
from typing import List, Optional, Tuple, Union

# Prohibited IPv4 Network Blocks
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

LOOPBACK_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

LINK_LOCAL_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
]

# Cloud Metadata IP Endpoints (AWS, GCP, Azure, Oracle Cloud IMDS)
CLOUD_METADATA_IPS = [
    ipaddress.ip_network("169.254.169.254/32"),  # AWS/GCP/Azure IMDS IPv4
    ipaddress.ip_network("169.254.169.253/32"),  # GCP Internal DNS IPv4
    ipaddress.ip_network("fd00:ec2::254/128"),    # AWS IMDSv2 IPv6
]

DOCUMENTATION_TEST_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("2001:db8::/32"),       # Documentation IPv6 (RFC 3849)
]

# Additional Reserved, Multicast, CGNAT, and Special Purpose
OTHER_RESERVED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # Current network (RFC 1122)
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT (RFC 6598)
    ipaddress.ip_network("192.0.0.0/24"),        # IETF Protocol (RFC 6890)
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmark (RFC 2544)
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast (RFC 5771)
    ipaddress.ip_network("240.0.0.0/4"),         # Class E Reserved (RFC 1112)
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast (RFC 919)
    # IPv6
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("::ffff:0:0/96"),       # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),            # Discard-only (RFC 6666)
    ipaddress.ip_network("fc00::/7"),            # Unique Local Address ULA (RFC 4193)
    ipaddress.ip_network("ff00::/8"),            # Multicast IPv6 (RFC 4291)
]

IPV6_6TO4_PREFIX = ipaddress.ip_network("2002::/16")


def _parse_int_auto(p: str) -> int:
    """Parses decimal, hex (0x...), or octal (0...) string according to inet_aton rules."""
    cleaned = p.strip()
    if cleaned.lower().startswith("0x"):
        return int(cleaned, 16)
    elif cleaned.startswith("0") and len(cleaned) > 1 and not cleaned.lower().startswith("0o"):
        return int(cleaned, 8)
    return int(cleaned, 10)


def parse_and_normalize_ip(
    ip_input: Union[str, int, ipaddress.IPv4Address, ipaddress.IPv6Address]
) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """
    Parses and normalizes standard, hexadecimal, octal, decimal, and IPv4-mapped IPv6 addresses.
    Returns None if the input is not a parseable IP address literal.
    """
    if isinstance(ip_input, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return ip_input
    if isinstance(ip_input, int):
        if 0 <= ip_input <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(ip_input)
        return None
    if not isinstance(ip_input, str):
        return None

    cleaned = ip_input.strip()
    if not cleaned:
        return None

    # Strip surrounding square brackets for IPv6 or bracketed IPv4
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1].strip()

    # Strip zone identifier if present (e.g. fe80::1%eth0)
    if "%" in cleaned:
        cleaned = cleaned.split("%")[0].strip()

    # 1. Pure decimal or octal integer without dots (e.g. "2130706433" -> 127.0.0.1 or "017700000001")
    if cleaned.isdigit() and "." not in cleaned and ":" not in cleaned:
        try:
            val = _parse_int_auto(cleaned)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # 2. Hexadecimal single number (e.g. "0x7f000001" -> 127.0.0.1)
    if cleaned.lower().startswith("0x") and "." not in cleaned:
        try:
            val = int(cleaned, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # 3. Dotted IPv4 with potential hex/octal mixed parts (e.g. "0177.0.0.1", "0x7f.0.0.1", "127.1")
    if "." in cleaned and ":" not in cleaned:
        parts = cleaned.split(".")
        if 1 <= len(parts) <= 4:
            parsed_parts = []
            valid_parts = True
            for part in parts:
                p = part.strip()
                if not p:
                    valid_parts = False
                    break
                try:
                    val = _parse_int_auto(p)
                    parsed_parts.append(val)
                except (ValueError, OverflowError):
                    valid_parts = False
                    break
            if valid_parts and len(parsed_parts) == len(parts):
                try:
                    if len(parts) == 4:
                        if all(0 <= p <= 255 for p in parsed_parts):
                            val = (parsed_parts[0] << 24) + (parsed_parts[1] << 16) + (parsed_parts[2] << 8) + parsed_parts[3]
                            return ipaddress.IPv4Address(val)
                    elif len(parts) == 3:
                        if 0 <= parsed_parts[0] <= 255 and 0 <= parsed_parts[1] <= 255 and 0 <= parsed_parts[2] <= 0xFFFF:
                            val = (parsed_parts[0] << 24) + (parsed_parts[1] << 16) + parsed_parts[2]
                            return ipaddress.IPv4Address(val)
                    elif len(parts) == 2:
                        if 0 <= parsed_parts[0] <= 255 and 0 <= parsed_parts[1] <= 0xFFFFFF:
                            val = (parsed_parts[0] << 24) + parsed_parts[1]
                            return ipaddress.IPv4Address(val)
                    elif len(parts) == 1:
                        if 0 <= parsed_parts[0] <= 0xFFFFFFFF:
                            return ipaddress.IPv4Address(parsed_parts[0])
                except Exception:
                    pass

    # 4. Standard ipaddress parser (handles standard dotted-quad IPv4 and RFC 4291 IPv6)
    try:
        return ipaddress.ip_address(cleaned)

    except ValueError:
        pass

    return None


def is_prohibited_ip(
    ip_in: Union[str, int, ipaddress.IPv4Address, ipaddress.IPv6Address],
    environment_class: str = "bounty",
) -> Tuple[bool, str]:
    """
    Evaluates whether an IP address is prohibited under Anti-SSRF and Safe Harbor policies.
    Returns (True, reason) if prohibited, or (False, reason) if permitted.
    
    In 'bounty' mode:
      All private (RFC 1918), loopback, link-local, cloud metadata, and special-use IPs are blocked.
    In 'lab' mode:
      RFC 1918 and loopback are permitted for local fixture testing, BUT cloud metadata remains BLOCKED.
    """
    ip = parse_and_normalize_ip(ip_in)
    if ip is None:
        # Not a valid IP literal
        return False, "NOT_AN_IP_LITERAL"

    # Unwrap IPv4-mapped IPv6 address (::ffff:x.x.x.x)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ipv4_equivalent = ip.ipv4_mapped
        # Evaluate against IPv4 rules first
        prohibited, reason = is_prohibited_ip(ipv4_equivalent, environment_class=environment_class)
        if prohibited:
            return True, f"IPV4_MAPPED_IPV6: {reason}"

    # Unwrap 6to4 embedded IPv4 address (2002:xxxx:xxxx::)
    if isinstance(ip, ipaddress.IPv6Address) and ip in IPV6_6TO4_PREFIX:
        embedded_v4 = ipaddress.IPv4Address(ip.packed[2:6])
        prohibited, reason = is_prohibited_ip(embedded_v4, environment_class=environment_class)
        if prohibited:
            return True, f"6TO4_EMBEDDED_IPV4: {reason}"

    # 1. Cloud Metadata Check (Unconditionally prohibited in ALL environments including 'lab')
    for net in CLOUD_METADATA_IPS:
        if ip in net:
            return True, f"CLOUD_METADATA_PROHIBITED ({net})"

    # 2. Lab Environment Check
    if environment_class.lower() == "lab":
        # In lab mode, permit RFC 1918, loopback, and documentation test subnets
        for net in RFC1918_NETWORKS:
            if ip in net:
                return False, f"ALLOWED_IN_LAB (RFC1918 {net})"
        for net in LOOPBACK_NETWORKS:
            if ip in net:
                return False, f"ALLOWED_IN_LAB (Loopback {net})"
        for net in DOCUMENTATION_TEST_NETWORKS:
            if ip in net:
                return False, f"ALLOWED_IN_LAB (Documentation {net})"

    # 3. Loopback
    for net in LOOPBACK_NETWORKS:
        if ip in net:
            return True, f"LOOPBACK_IP_PROHIBITED ({net})"

    # 4. RFC 1918 Private IPv4
    for net in RFC1918_NETWORKS:
        if ip in net:
            return True, f"RFC1918_PRIVATE_IP_PROHIBITED ({net})"

    # 5. Link-Local
    for net in LINK_LOCAL_NETWORKS:
        if ip in net:
            return True, f"LINK_LOCAL_IP_PROHIBITED ({net})"

    # 6. Documentation Networks (Prohibited in bounty mode)
    for net in DOCUMENTATION_TEST_NETWORKS:
        if ip in net:
            return True, f"DOCUMENTATION_NETWORK_PROHIBITED ({net})"

    # 7. Other Reserved / Multicast / CGNAT
    for net in OTHER_RESERVED_NETWORKS:
        if ip in net:
            return True, f"RESERVED_OR_SPECIAL_IP_PROHIBITED ({net})"

    return False, "PUBLIC_IP_ALLOWED"


def resolve_host(hostname: str) -> List[str]:
    """
    Resolves hostname to list of IP string representations using standard DNS resolution.
    Returns empty list if resolution fails.
    """
    ips: List[str] = []
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for entry in addr_info:
            sockaddr = entry[4]
            ip_str = sockaddr[0]
            if ip_str not in ips:
                ips.append(ip_str)
    except Exception:
        pass
    return ips


def check_dns_rebinding(
    hostname: str,
    environment_class: str = "bounty",
    resolved_ips: Optional[List[str]] = None,
) -> Tuple[bool, List[str], str]:
    """
    Performs pre-flight DNS rebinding inspection.
    Validates that none of the resolved A/AAAA addresses belong to prohibited IP space.
    If resolved_ips is passed, validates those directly without network DNS query.
    """
    ips = resolved_ips if resolved_ips is not None else resolve_host(hostname)
    if not ips:
        return False, [], "DNS_RESOLUTION_FAILED"

    for ip_str in ips:
        prohibited, reason = is_prohibited_ip(ip_str, environment_class=environment_class)
        if prohibited:
            return False, ips, f"DNS_REBINDING_OR_PROHIBITED_IP: {ip_str} is {reason}"

    return True, ips, "ALL_IPS_PERMITTED"
