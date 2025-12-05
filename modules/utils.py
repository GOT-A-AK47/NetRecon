"""
Utility Functions
Common helper functions used across modules.
"""

import re
import socket
import struct
import ipaddress
from typing import List, Tuple, Optional


def validate_ip(ip: str) -> bool:
    """
    Validate if string is a valid IP address

    Args:
        ip: IP address string

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_network(network: str) -> bool:
    """
    Validate if string is a valid network CIDR notation

    Args:
        network: Network string (e.g., "192.168.1.0/24")

    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_network(network, strict=False)
        return True
    except ValueError:
        return False


def parse_port_range(port_string: str) -> List[int]:
    """
    Parse port range string into list of ports

    Args:
        port_string: Port specification (e.g., "80,443,8000-8100")

    Returns:
        List of port numbers
    """
    ports = []

    for part in port_string.split(','):
        part = part.strip()

        if '-' in part:
            # Range
            try:
                start, end = part.split('-')
                start, end = int(start), int(end)
                if 1 <= start <= 65535 and 1 <= end <= 65535 and start <= end:
                    ports.extend(range(start, end + 1))
            except ValueError:
                continue
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
            except ValueError:
                continue

    return sorted(list(set(ports)))


def resolve_hostname(hostname: str) -> Optional[str]:
    """
    Resolve hostname to IP address

    Args:
        hostname: Hostname to resolve

    Returns:
        IP address or None if resolution fails
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup

    Args:
        ip: IP address

    Returns:
        Hostname or None if lookup fails
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def get_service_name(port: int, protocol: str = 'tcp') -> str:
    """
    Get common service name for a port

    Args:
        port: Port number
        protocol: Protocol type (tcp/udp)

    Returns:
        Service name or 'unknown'
    """
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        # Common services not in getservbyport
        common_services = {
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            8080: 'http-proxy',
            8443: 'https-alt',
            27017: 'mongodb',
        }
        return common_services.get(port, 'unknown')


def format_mac(mac_bytes: bytes) -> str:
    """
    Format MAC address bytes to readable string

    Args:
        mac_bytes: MAC address as bytes

    Returns:
        Formatted MAC address (e.g., "AA:BB:CC:DD:EE:FF")
    """
    return ':'.join(f'{b:02X}' for b in mac_bytes)


def mac_to_bytes(mac_string: str) -> bytes:
    """
    Convert MAC address string to bytes

    Args:
        mac_string: MAC address string

    Returns:
        MAC address as bytes
    """
    mac_string = mac_string.replace(':', '').replace('-', '')
    return bytes.fromhex(mac_string)


def format_bytes(bytes_count: int) -> str:
    """
    Format byte count to human readable string

    Args:
        bytes_count: Number of bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_count < 1024.0:
            return f"{bytes_count:.2f} {unit}"
        bytes_count /= 1024.0
    return f"{bytes_count:.2f} PB"


def get_network_range(network: str) -> List[str]:
    """
    Get all IP addresses in a network range

    Args:
        network: Network in CIDR notation

    Returns:
        List of IP addresses
    """
    try:
        net = ipaddress.ip_network(network, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return []


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private

    Args:
        ip: IP address string

    Returns:
        True if private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def calculate_checksum(data: bytes) -> int:
    """
    Calculate IP checksum

    Args:
        data: Data bytes

    Returns:
        Checksum value
    """
    checksum = 0

    # Add all 16-bit words
    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            word = (data[i] << 8) + data[i + 1]
        else:
            word = data[i] << 8
        checksum += word

    # Add carry and take one's complement
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF

    return checksum


def parse_cidr(cidr: str) -> Tuple[str, int]:
    """
    Parse CIDR notation

    Args:
        cidr: CIDR string (e.g., "192.168.1.0/24")

    Returns:
        Tuple of (network_address, prefix_length)
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return (str(network.network_address), network.prefixlen)
    except ValueError:
        return ('0.0.0.0', 0)


def get_protocol_name(protocol_number: int) -> str:
    """
    Get protocol name from number

    Args:
        protocol_number: IP protocol number

    Returns:
        Protocol name
    """
    protocols = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        41: 'IPv6',
        47: 'GRE',
        50: 'ESP',
        51: 'AH',
        89: 'OSPF',
    }
    return protocols.get(protocol_number, f'Protocol-{protocol_number}')
