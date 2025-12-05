"""
Port Scanner Module
Performs TCP/UDP port scanning with service detection.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from datetime import datetime

from .utils import validate_ip, resolve_hostname, parse_port_range, get_service_name


class PortScanner:
    """Port scanner with multi-threading support"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.timeout = config.get('port_scanner.scan_timeout', 1)
        self.max_threads = config.get('network.max_threads', 100)
        self.service_detection = config.get('port_scanner.service_detection', True)

    def scan(self, target: str, ports: str = None) -> Dict:
        """
        Scan target for open ports

        Args:
            target: IP address or hostname
            ports: Port specification (e.g., "80,443,8000-8100")

        Returns:
            Dictionary with scan results
        """
        self.logger.info(f"Starting port scan on {target}")

        # Resolve target if it's a hostname
        if not validate_ip(target):
            resolved_ip = resolve_hostname(target)
            if not resolved_ip:
                self.logger.error(f"Could not resolve hostname: {target}")
                return {'error': 'Could not resolve hostname', 'target': target}
            target_ip = resolved_ip
        else:
            target_ip = target

        # Parse ports
        if ports is None:
            ports = self.config.get('port_scanner.default_ports', '1-1000')

        port_list = parse_port_range(ports)
        self.logger.info(f"Scanning {len(port_list)} ports on {target_ip}")

        # Scan ports
        start_time = datetime.now()
        results = {
            'target': target,
            'ip': target_ip,
            'scan_start': start_time.isoformat(),
            'ports': []
        }

        # Multi-threaded scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, target_ip, port, 'tcp'): port
                for port in port_list
            }

            for future in as_completed(futures):
                port_result = future.result()
                if port_result:
                    results['ports'].append(port_result)

        # Sort results by port number
        results['ports'].sort(key=lambda x: x['port'])

        end_time = datetime.now()
        results['scan_end'] = end_time.isoformat()
        results['duration'] = (end_time - start_time).total_seconds()
        results['open_ports'] = len([p for p in results['ports'] if p['open']])

        self.logger.info(f"Scan complete: {results['open_ports']} open ports found")

        return results

    def _scan_port(self, ip: str, port: int, protocol: str = 'tcp') -> Optional[Dict]:
        """
        Scan a single port

        Args:
            ip: Target IP address
            port: Port number
            protocol: Protocol (tcp/udp)

        Returns:
            Port information dict or None
        """
        try:
            if protocol == 'tcp':
                return self._scan_tcp_port(ip, port)
            elif protocol == 'udp':
                return self._scan_udp_port(ip, port)
        except Exception as e:
            self.logger.debug(f"Error scanning port {port}: {e}")
            return None

    def _scan_tcp_port(self, ip: str, port: int) -> Optional[Dict]:
        """
        Perform TCP connect scan

        Args:
            ip: Target IP
            port: Port number

        Returns:
            Port information or None
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        result = {
            'port': port,
            'protocol': 'tcp',
            'open': False,
            'service': 'unknown'
        }

        try:
            # Attempt connection
            conn_result = sock.connect_ex((ip, port))

            if conn_result == 0:
                result['open'] = True

                # Service detection
                if self.service_detection:
                    result['service'] = get_service_name(port, 'tcp')

                    # Try to grab banner
                    banner = self._grab_banner(sock)
                    if banner:
                        result['banner'] = banner

                self.logger.debug(f"Port {port}/tcp is open")

        except socket.timeout:
            pass
        except socket.error as e:
            self.logger.debug(f"Socket error on port {port}: {e}")
        finally:
            sock.close()

        return result if result['open'] else None

    def _scan_udp_port(self, ip: str, port: int) -> Optional[Dict]:
        """
        Perform UDP scan

        Args:
            ip: Target IP
            port: Port number

        Returns:
            Port information or None

        Note: UDP scanning is less reliable than TCP
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)

        result = {
            'port': port,
            'protocol': 'udp',
            'open': False,
            'service': 'unknown'
        }

        try:
            # Send empty packet
            sock.sendto(b'', (ip, port))

            # Wait for response
            try:
                data, _ = sock.recvfrom(1024)
                result['open'] = True
                if self.service_detection:
                    result['service'] = get_service_name(port, 'udp')
            except socket.timeout:
                # No response might mean open or filtered
                result['state'] = 'open|filtered'

        except socket.error:
            pass
        finally:
            sock.close()

        return result if result.get('open') or result.get('state') else None

    def _grab_banner(self, sock: socket.socket) -> Optional[str]:
        """
        Try to grab service banner

        Args:
            sock: Connected socket

        Returns:
            Banner string or None
        """
        try:
            sock.settimeout(2)
            # Try to receive banner
            banner = sock.recv(1024)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()
        except:
            pass

        return None

    def scan_common_ports(self, target: str) -> Dict:
        """
        Quick scan of common ports

        Args:
            target: IP or hostname

        Returns:
            Scan results
        """
        common_ports = self.config.get('port_scanner.common_ports', [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 8080
        ])

        port_string = ','.join(map(str, common_ports))
        return self.scan(target, port_string)

    def stop(self):
        """Stop scanning"""
        self.logger.info("Port scanner stopped")
