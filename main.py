#!/usr/bin/env python3
"""
NetRecon - Network Reconnaissance & Analysis Tool
Educational security tool for authorized network testing only.

WARNING: Only use on networks you own or have explicit permission to test.
Unauthorized network scanning and packet capture may be illegal.
"""

import logging
import signal
import sys
import argparse
from threading import Thread

from modules.port_scanner import PortScanner
from modules.packet_analyzer import PacketAnalyzer
from modules.host_discovery import HostDiscovery
from modules.web_interface import WebInterface
from modules.config_loader import Config


class NetRecon:
    def __init__(self, config_file='config.json'):
        self.config = Config(config_file)
        self.running = False

        # Initialize modules
        self.port_scanner = PortScanner(self.config)
        self.packet_analyzer = PacketAnalyzer(self.config)
        self.host_discovery = HostDiscovery(self.config)
        self.web_interface = WebInterface(self.config)

        # Setup logging
        log_level = getattr(logging, self.config.get('log_level', 'INFO'))
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.config.get('log_file', 'logs/netrecon.log')),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, sig, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info("Shutdown signal received, cleaning up...")
        self.stop()
        sys.exit(0)

    def start_cli_mode(self, args):
        """Start in CLI mode with specified action"""
        self.logger.info("Starting NetRecon in CLI mode...")

        if args.scan:
            self._run_port_scan(args.scan, args.ports)
        elif args.discover:
            self._run_host_discovery(args.discover)
        elif args.capture:
            self._run_packet_capture(args.interface, args.filter)
        else:
            self.logger.error("No valid action specified. Use --help for usage.")

    def start_interactive_mode(self):
        """Start in interactive mode with web interface"""
        self.logger.info("Starting NetRecon in interactive mode...")
        self.running = True

        # Start web interface in separate thread
        if self.config.get('web_enabled', True):
            web_thread = Thread(target=self.web_interface.start, daemon=True)
            web_thread.start()
            self.logger.info(f"Web interface available at http://{self.config.get('web_host')}:{self.config.get('web_port')}")

        # Keep main thread alive
        try:
            while self.running:
                signal.pause()
        except KeyboardInterrupt:
            self.stop()

    def _run_port_scan(self, target, ports):
        """Run port scan on target"""
        self.logger.info(f"Starting port scan on {target}")
        results = self.port_scanner.scan(target, ports)
        self._display_scan_results(results)

    def _run_host_discovery(self, network):
        """Run host discovery on network"""
        self.logger.info(f"Starting host discovery on {network}")
        hosts = self.host_discovery.discover(network)
        self._display_discovered_hosts(hosts)

    def _run_packet_capture(self, interface, capture_filter):
        """Run packet capture"""
        self.logger.info(f"Starting packet capture on {interface}")
        self.packet_analyzer.start_capture(interface, capture_filter)

        try:
            while True:
                signal.pause()
        except KeyboardInterrupt:
            self.packet_analyzer.stop_capture()

    def _display_scan_results(self, results):
        """Display port scan results"""
        print("\n" + "="*60)
        print(f"Scan Results for {results.get('target', 'Unknown')}")
        print("="*60)

        for port_info in results.get('ports', []):
            status = "OPEN" if port_info['open'] else "CLOSED"
            service = port_info.get('service', 'unknown')
            print(f"Port {port_info['port']}/{port_info['protocol']}: {status} ({service})")

        print("="*60 + "\n")

    def _display_discovered_hosts(self, hosts):
        """Display discovered hosts"""
        print("\n" + "="*60)
        print(f"Discovered Hosts ({len(hosts)} found)")
        print("="*60)

        for host in hosts:
            print(f"IP: {host['ip']:<15} MAC: {host.get('mac', 'N/A'):<17} Hostname: {host.get('hostname', 'N/A')}")

        print("="*60 + "\n")

    def stop(self):
        """Stop all modules"""
        self.logger.info("Stopping NetRecon...")
        self.running = False
        self.packet_analyzer.stop()
        self.web_interface.stop()


def print_banner():
    """Print application banner"""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║        NetRecon v1.0.0                   ║
    ║  Network Reconnaissance & Analysis Tool   ║
    ╚═══════════════════════════════════════════╝

    WARNING: Educational use only!
    Only use on networks you own or have
    explicit permission to test.
    """
    print(banner)


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='NetRecon - Network Reconnaissance & Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--config', type=str, default='config.json',
                        help='Path to configuration file')

    # Operation modes
    parser.add_argument('--scan', type=str, metavar='TARGET',
                        help='Run port scan on target (IP or hostname)')
    parser.add_argument('--discover', type=str, metavar='NETWORK',
                        help='Discover hosts on network (e.g., 192.168.1.0/24)')
    parser.add_argument('--capture', action='store_true',
                        help='Start packet capture')
    parser.add_argument('--interactive', action='store_true',
                        help='Start in interactive mode with web interface')

    # Scan options
    parser.add_argument('--ports', type=str, default='1-1000',
                        help='Port range to scan (default: 1-1000)')
    parser.add_argument('--interface', type=str, default='eth0',
                        help='Network interface for packet capture')
    parser.add_argument('--filter', type=str, default='',
                        help='BPF filter for packet capture')

    args = parser.parse_args()

    # Create NetRecon instance
    netrecon = NetRecon(args.config)

    # Determine operation mode
    if args.interactive:
        netrecon.start_interactive_mode()
    elif args.scan or args.discover or args.capture:
        netrecon.start_cli_mode(args)
    else:
        # Default to interactive mode
        netrecon.start_interactive_mode()


if __name__ == "__main__":
    main()
