"""
Host Discovery Module
Discovers active hosts on a network using various techniques.
"""

import logging
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

from .utils import validate_network, get_network_range, reverse_dns

try:
    from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class HostDiscovery:
    """Network host discovery tool"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.max_threads = config.get('network.max_threads', 100)
        self.timeout = config.get('network.timeout', 2)
        self.resolve_hostnames = config.get('host_discovery.resolve_hostnames', True)

    def discover(self, network: str, method: str = 'auto') -> List[Dict]:
        """
        Discover active hosts on network

        Args:
            network: Network in CIDR notation (e.g., "192.168.1.0/24")
            method: Discovery method (ping, arp, auto)

        Returns:
            List of discovered hosts
        """
        if not validate_network(network):
            self.logger.error(f"Invalid network: {network}")
            return []

        self.logger.info(f"Starting host discovery on {network}")

        # Choose method
        if method == 'auto':
            if SCAPY_AVAILABLE:
                method = 'arp'
            else:
                method = 'ping'

        # Perform discovery
        if method == 'arp' and SCAPY_AVAILABLE:
            hosts = self._discover_arp(network)
        elif method == 'ping':
            hosts = self._discover_ping(network)
        else:
            self.logger.error(f"Invalid or unavailable method: {method}")
            return []

        # Resolve hostnames if enabled
        if self.resolve_hostnames:
            for host in hosts:
                hostname = reverse_dns(host['ip'])
                if hostname:
                    host['hostname'] = hostname

        self.logger.info(f"Discovery complete: {len(hosts)} hosts found")
        return hosts

    def _discover_arp(self, network: str) -> List[Dict]:
        """
        Discover hosts using ARP scanning (Layer 2)

        Args:
            network: Network CIDR

        Returns:
            List of discovered hosts
        """
        self.logger.info(f"Performing ARP scan on {network}")

        hosts = []

        try:
            # Create ARP request
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # Send and receive
            answered, unanswered = srp(
                arp_request_broadcast,
                timeout=self.timeout,
                verbose=False
            )

            # Process responses
            for sent, received in answered:
                host_info = {
                    'ip': received.psrc,
                    'mac': received.hwsrc,
                    'method': 'arp'
                }
                hosts.append(host_info)
                self.logger.debug(f"Found: {host_info['ip']} ({host_info['mac']})")

        except Exception as e:
            self.logger.error(f"Error during ARP scan: {e}", exc_info=True)

        return hosts

    def _discover_ping(self, network: str) -> List[Dict]:
        """
        Discover hosts using ICMP ping

        Args:
            network: Network CIDR

        Returns:
            List of discovered hosts
        """
        self.logger.info(f"Performing ping scan on {network}")

        # Get all IPs in range
        ip_list = get_network_range(network)
        hosts = []

        # Multi-threaded ping
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._ping_host, ip): ip
                for ip in ip_list
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    hosts.append(result)

        return hosts

    def _ping_host(self, ip: str) -> Dict:
        """
        Ping a single host

        Args:
            ip: IP address

        Returns:
            Host info dict or None
        """
        try:
            # Use system ping command (more reliable than ICMP with raw sockets)
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            timeout_param = '-w' if platform.system().lower() == 'windows' else '-W'

            command = ['ping', param, '1', timeout_param, str(self.timeout), ip]

            result = subprocess.run(
                command,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 1
            )

            if result.returncode == 0:
                self.logger.debug(f"Host {ip} is up")
                return {
                    'ip': ip,
                    'method': 'ping',
                    'status': 'up'
                }

        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.logger.debug(f"Error pinging {ip}: {e}")

        return None

    def _discover_icmp_scapy(self, network: str) -> List[Dict]:
        """
        Discover hosts using Scapy ICMP (alternative to system ping)

        Args:
            network: Network CIDR

        Returns:
            List of discovered hosts
        """
        if not SCAPY_AVAILABLE:
            return []

        self.logger.info(f"Performing ICMP scan with Scapy on {network}")

        ip_list = get_network_range(network)
        hosts = []

        for ip in ip_list:
            try:
                # Send ICMP echo request
                packet = IP(dst=ip) / ICMP()
                response = sr1(packet, timeout=self.timeout, verbose=False)

                if response:
                    host_info = {
                        'ip': ip,
                        'method': 'icmp',
                        'status': 'up'
                    }
                    hosts.append(host_info)
                    self.logger.debug(f"Host {ip} is up")

            except Exception as e:
                self.logger.debug(f"Error with ICMP to {ip}: {e}")

        return hosts

    def check_host(self, ip: str) -> bool:
        """
        Quick check if a host is up

        Args:
            ip: IP address

        Returns:
            True if host is up
        """
        result = self._ping_host(ip)
        return result is not None

    def discover_fast(self, network: str) -> List[str]:
        """
        Fast discovery returning only IPs

        Args:
            network: Network CIDR

        Returns:
            List of IP addresses
        """
        hosts = self.discover(network)
        return [host['ip'] for host in hosts]

    def scan_subnet(self, ip: str, prefix: int = 24) -> List[Dict]:
        """
        Scan the subnet of a given IP

        Args:
            ip: IP address
            prefix: Network prefix length

        Returns:
            List of discovered hosts
        """
        network = f"{ip}/{prefix}"
        return self.discover(network)
