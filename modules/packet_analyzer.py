"""
Packet Analyzer Module
Captures and analyzes network packets using Scapy.
"""

import logging
import os
from datetime import datetime
from threading import Thread, Event
from typing import Optional, Dict, List

try:
    from scapy.all import (
        sniff, wrpcap, Ether, IP, TCP, UDP, ICMP, ARP, DNS, Raw
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class PacketAnalyzer:
    """Real-time packet capture and analysis"""

    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(__name__)

        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available. Install with: pip install scapy")
            return

        self.capture_dir = config.get('packet_analyzer.capture_dir', 'data/captures')
        self.max_packets = config.get('packet_analyzer.max_packets', 10000)
        self.auto_save = config.get('packet_analyzer.auto_save', True)

        # Create capture directory
        os.makedirs(self.capture_dir, exist_ok=True)

        # Capture state
        self.capturing = False
        self.capture_thread = None
        self.stop_event = Event()
        self.packets = []
        self.statistics = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'other': 0
        }

    def start_capture(self, interface: str = None, capture_filter: str = '', packet_count: int = 0):
        """
        Start packet capture

        Args:
            interface: Network interface (None for default)
            capture_filter: BPF filter string
            packet_count: Max packets to capture (0 = unlimited)
        """
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available")
            return

        if self.capturing:
            self.logger.warning("Capture already in progress")
            return

        if interface is None:
            interface = self.config.get('network.default_interface', 'eth0')

        self.logger.info(f"Starting packet capture on {interface}")
        if capture_filter:
            self.logger.info(f"Using filter: {capture_filter}")

        self.capturing = True
        self.stop_event.clear()
        self.packets = []
        self._reset_statistics()

        # Start capture in separate thread
        self.capture_thread = Thread(
            target=self._capture_packets,
            args=(interface, capture_filter, packet_count),
            daemon=True
        )
        self.capture_thread.start()

    def stop_capture(self):
        """Stop packet capture"""
        if not self.capturing:
            return

        self.logger.info("Stopping packet capture...")
        self.capturing = False
        self.stop_event.set()

        if self.capture_thread:
            self.capture_thread.join(timeout=5)

        # Auto-save if enabled
        if self.auto_save and self.packets:
            self.save_capture()

        self.logger.info(f"Capture stopped. Total packets: {len(self.packets)}")

    def _capture_packets(self, interface: str, capture_filter: str, packet_count: int):
        """
        Internal method to capture packets

        Args:
            interface: Network interface
            capture_filter: BPF filter
            packet_count: Max packets
        """
        try:
            count = packet_count if packet_count > 0 else 0

            sniff(
                iface=interface,
                prn=self._process_packet,
                filter=capture_filter if capture_filter else None,
                count=count,
                stop_filter=lambda x: self.stop_event.is_set()
            )
        except Exception as e:
            self.logger.error(f"Error during capture: {e}", exc_info=True)
        finally:
            self.capturing = False

    def _process_packet(self, packet):
        """
        Process captured packet

        Args:
            packet: Scapy packet object
        """
        # Check packet limit
        if len(self.packets) >= self.max_packets:
            self.logger.warning(f"Max packet limit ({self.max_packets}) reached")
            self.stop_event.set()
            return

        # Store packet
        self.packets.append(packet)

        # Update statistics
        self._update_statistics(packet)

        # Log interesting packets
        self._log_packet(packet)

    def _update_statistics(self, packet):
        """Update packet statistics"""
        self.statistics['total'] += 1

        if packet.haslayer(TCP):
            self.statistics['tcp'] += 1
        elif packet.haslayer(UDP):
            self.statistics['udp'] += 1
        elif packet.haslayer(ICMP):
            self.statistics['icmp'] += 1
        elif packet.haslayer(ARP):
            self.statistics['arp'] += 1
        else:
            self.statistics['other'] += 1

    def _log_packet(self, packet):
        """Log interesting packet information"""
        try:
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst

                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    flags = packet[TCP].flags
                    self.logger.debug(f"TCP {src}:{sport} -> {dst}:{dport} [{flags}]")

                elif packet.haslayer(UDP):
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    self.logger.debug(f"UDP {src}:{sport} -> {dst}:{dport}")

                    # Check for DNS
                    if packet.haslayer(DNS):
                        dns = packet[DNS]
                        if dns.qr == 0:  # Query
                            query = dns.qd.qname.decode() if dns.qd else 'unknown'
                            self.logger.info(f"DNS Query: {query}")

                elif packet.haslayer(ICMP):
                    icmp_type = packet[ICMP].type
                    self.logger.debug(f"ICMP {src} -> {dst} (type {icmp_type})")

            elif packet.haslayer(ARP):
                arp = packet[ARP]
                if arp.op == 1:  # Who-has
                    self.logger.debug(f"ARP Who-has {arp.pdst} from {arp.psrc}")
                elif arp.op == 2:  # Is-at
                    self.logger.debug(f"ARP {arp.psrc} is at {arp.hwsrc}")

        except Exception as e:
            self.logger.debug(f"Error logging packet: {e}")

    def save_capture(self, filename: str = None) -> str:
        """
        Save captured packets to PCAP file

        Args:
            filename: Output filename (auto-generated if None)

        Returns:
            Path to saved file
        """
        if not self.packets:
            self.logger.warning("No packets to save")
            return None

        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"capture_{timestamp}.pcap"

        filepath = os.path.join(self.capture_dir, filename)

        try:
            wrpcap(filepath, self.packets)
            self.logger.info(f"Capture saved to {filepath} ({len(self.packets)} packets)")
            return filepath
        except Exception as e:
            self.logger.error(f"Error saving capture: {e}")
            return None

    def get_statistics(self) -> Dict:
        """Get current capture statistics"""
        return {
            **self.statistics,
            'capturing': self.capturing,
            'packets_captured': len(self.packets)
        }

    def get_packets_summary(self, limit: int = 100) -> List[Dict]:
        """
        Get summary of captured packets

        Args:
            limit: Max packets to return

        Returns:
            List of packet summaries
        """
        summaries = []

        for i, packet in enumerate(self.packets[-limit:]):
            summary = {
                'index': i,
                'timestamp': packet.time,
                'length': len(packet)
            }

            if packet.haslayer(IP):
                summary['src'] = packet[IP].src
                summary['dst'] = packet[IP].dst
                summary['protocol'] = packet[IP].proto

                if packet.haslayer(TCP):
                    summary['sport'] = packet[TCP].sport
                    summary['dport'] = packet[TCP].dport
                    summary['proto_name'] = 'TCP'
                elif packet.haslayer(UDP):
                    summary['sport'] = packet[UDP].sport
                    summary['dport'] = packet[UDP].dport
                    summary['proto_name'] = 'UDP'
                elif packet.haslayer(ICMP):
                    summary['proto_name'] = 'ICMP'

            elif packet.haslayer(ARP):
                summary['proto_name'] = 'ARP'
                summary['src'] = packet[ARP].psrc
                summary['dst'] = packet[ARP].pdst

            summaries.append(summary)

        return summaries

    def analyze_traffic(self) -> Dict:
        """
        Analyze captured traffic

        Returns:
            Traffic analysis results
        """
        analysis = {
            'total_packets': len(self.packets),
            'protocols': self.statistics.copy(),
            'conversations': {},
            'top_talkers': {},
            'ports': {}
        }

        # Analyze conversations
        conversations = {}
        talkers = {}
        ports = {}

        for packet in self.packets:
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst

                # Track conversations
                conv_key = tuple(sorted([src, dst]))
                conversations[conv_key] = conversations.get(conv_key, 0) + 1

                # Track talkers
                talkers[src] = talkers.get(src, 0) + 1
                talkers[dst] = talkers.get(dst, 0) + 1

                # Track ports
                if packet.haslayer(TCP) or packet.haslayer(UDP):
                    layer = TCP if packet.haslayer(TCP) else UDP
                    sport = packet[layer].sport
                    dport = packet[layer].dport

                    ports[sport] = ports.get(sport, 0) + 1
                    ports[dport] = ports.get(dport, 0) + 1

        # Get top 10
        analysis['top_conversations'] = sorted(
            conversations.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        analysis['top_talkers'] = sorted(
            talkers.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        analysis['top_ports'] = sorted(
            ports.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]

        return analysis

    def _reset_statistics(self):
        """Reset statistics counters"""
        self.statistics = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'arp': 0,
            'other': 0
        }

    def stop(self):
        """Stop analyzer"""
        self.stop_capture()
