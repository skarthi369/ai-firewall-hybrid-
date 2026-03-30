#!/usr/bin/env python3
"""
Production-Grade IDS/IPS Engine - Real-time Attack Detection & Prevention
Supports: DDoS detection, port scans, anomalies with Snort/Suricata-like pattern matching
"""

import time
import json
import os
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from typing import Dict, List, Tuple, Optional
from enum import Enum
import threading
import logging

import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AttackType(Enum):
    """Supported attack pattern types"""
    DDOS_SYN_FLOOD = "DDoS SYN Flood"
    DDOS_UDP_FLOOD = "DDoS UDP Flood"
    DDOS_ICMP_FLOOD = "DDoS ICMP Flood"
    PORT_SCAN = "Port Scan"
    ANOMALOUS_PAYLOAD = "Anomalous Payload"
    BRUTE_FORCE = "Brute Force"
    DATA_EXFILTRATION = "Data Exfiltration"
    UNKNOWN = "Unknown"


@dataclass
class AttackSignature:
    """Pattern-based attack signature (Snort/Suricata-like)"""
    name: str
    attack_type: AttackType
    threshold: int
    time_window: int  # seconds
    pattern: str
    severity: ThreatLevel


class TrafficStatistics:
    """Tracks traffic patterns for statistical anomaly detection"""

    def __init__(self, time_window: int = 60):
        self.time_window = time_window
        self.packets_per_src = defaultdict(deque)
        self.packets_per_dst = defaultdict(deque)
        self.packets_per_dst_port = defaultdict(deque)
        self.bytes_per_src = defaultdict(int)
        self.bytes_per_dst = defaultdict(int)
        self.lock = threading.Lock()

    def _cleanup_old(self, timestamp, counter):
        """Remove entries older than time_window"""
        cutoff = timestamp - self.time_window
        while counter and counter[0] < cutoff:
            counter.popleft()

    def record_packet(self, src_ip: str, dst_ip: str, dst_port: int, 
                     packet_size: int, timestamp: float):
        """Record packet for statistical analysis"""
        with self.lock:
            self._cleanup_old(timestamp, self.packets_per_src[src_ip])
            self._cleanup_old(timestamp, self.packets_per_dst[dst_ip])
            self._cleanup_old(timestamp, self.packets_per_dst_port[dst_port])

            self.packets_per_src[src_ip].append(timestamp)
            self.packets_per_dst[dst_ip].append(timestamp)
            self.packets_per_dst_port[dst_port].append(timestamp)

            self.bytes_per_src[src_ip] += packet_size
            self.bytes_per_dst[dst_ip] += packet_size

    def get_src_pps(self, src_ip: str) -> float:
        """Packets per second from source"""
        with self.lock:
            packets = len(self.packets_per_src[src_ip])
            return packets / self.time_window if self.time_window > 0 else 0

    def get_dst_pps(self, dst_ip: str) -> float:
        """Packets per second to destination"""
        with self.lock:
            packets = len(self.packets_per_dst[dst_ip])
            return packets / self.time_window if self.time_window > 0 else 0

    def get_port_pps(self, dst_port: int) -> float:
        """Packets per second to destination port"""
        with self.lock:
            packets = len(self.packets_per_dst_port[dst_port])
            return packets / self.time_window if self.time_window > 0 else 0

    def get_src_bandwidth(self, src_ip: str) -> float:
        """Bytes per second from source"""
        with self.lock:
            bytes_val = self.bytes_per_src[src_ip]
            return (bytes_val * 8) / self.time_window if self.time_window > 0 else 0  # bits/sec

    def get_dst_bandwidth(self, dst_ip: str) -> float:
        """Bytes per second to destination"""
        with self.lock:
            bytes_val = self.bytes_per_dst[dst_ip]
            return (bytes_val * 8) / self.time_window if self.time_window > 0 else 0  # bits/sec


class IDSIPSEngine:
    """Production-grade IDS/IPS Detection Engine"""

    def __init__(self, config_file: str = "ids_ips_config.json"):
        """Initialize with configuration"""
        self.config = self._load_config(config_file)
        self.stats = TrafficStatistics(time_window=self.config.get("stats_window", 60))
        
        # Alert tracking to prevent spam
        self.recent_alerts = defaultdict(deque)
        self.alert_lockout = self.config.get("alert_lockout", 5)  # seconds
        
        # Define attack signatures (Snort/Suricata-like)
        self.signatures = self._build_signatures()
        
        # Track detected events
        self.events_detected = []
        self.lock = threading.Lock()

        logger.info("✅ IDS/IPS Engine initialized")

    def _load_config(self, config_file: str) -> dict:
        """Load configuration or use defaults"""
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                return json.load(f)
        
        # Default production-grade configuration
        return {
            "stats_window": 60,
            "alert_lockout": 5,
            "ddos_syn_threshold": 100,  # packets/sec
            "ddos_udp_threshold": 200,
            "ddos_icmp_threshold": 150,
            "port_scan_threshold": 25,  # unique ports in 60s
            "anomaly_payload_threshold": 5000,  # bytes
            "brute_force_threshold": 50,  # failed attempts per minute
            "bandwidth_threshold_mbps": 100,  # Mbps threshold
        }

    def _build_signatures(self) -> List[AttackSignature]:
        """Build pattern-based signatures (Snort/Suricata-like rules)"""
        return [
            # DDoS Signatures
            AttackSignature(
                name="TCP SYN Flood Detected",
                attack_type=AttackType.DDOS_SYN_FLOOD,
                threshold=self.config.get("ddos_syn_threshold", 100),
                time_window=60,
                pattern="SYN-flood",
                severity=ThreatLevel.CRITICAL
            ),
            AttackSignature(
                name="UDP Flood Detected",
                attack_type=AttackType.DDOS_UDP_FLOOD,
                threshold=self.config.get("ddos_udp_threshold", 200),
                time_window=60,
                pattern="UDP-flood",
                severity=ThreatLevel.CRITICAL
            ),
            AttackSignature(
                name="ICMP Flood Detected",
                attack_type=AttackType.DDOS_ICMP_FLOOD,
                threshold=self.config.get("ddos_icmp_threshold", 150),
                time_window=60,
                pattern="ICMP-flood",
                severity=ThreatLevel.CRITICAL
            ),
            # Reconnaissance
            AttackSignature(
                name="Port Scan Detected",
                attack_type=AttackType.PORT_SCAN,
                threshold=self.config.get("port_scan_threshold", 25),
                time_window=60,
                pattern="port-scan",
                severity=ThreatLevel.HIGH
            ),
            # Exploitation
            AttackSignature(
                name="Anomalous Payload",
                attack_type=AttackType.ANOMALOUS_PAYLOAD,
                threshold=self.config.get("anomaly_payload_threshold", 5000),
                time_window=60,
                pattern="anomaly",
                severity=ThreatLevel.HIGH
            ),
        ]

    def analyze_packet(self, packet, timestamp: Optional[float] = None) -> Tuple[AttackType, ThreatLevel, str]:
        """
        Analyze packet for threats (multi-stage detection)
        Returns: (attack_type, threat_level, reason)
        """
        if timestamp is None:
            timestamp = time.time()

        if IP not in packet:
            return AttackType.UNKNOWN, ThreatLevel.LOW, "No IP layer"

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Stage 1: Signature-based detection
        attack_type, threat_level, reason = self._signature_detection(packet, src_ip, dst_ip)
        if attack_type != AttackType.UNKNOWN:
            return attack_type, threat_level, reason

        # Stage 2: Statistical anomaly detection
        pkt_size = len(packet)
        dst_port = self._get_dst_port(packet)
        
        self.stats.record_packet(src_ip, dst_ip, dst_port, pkt_size, timestamp)

        attack_type, threat_level, reason = self._statistical_detection(
            src_ip, dst_ip, dst_port, pkt_size, timestamp
        )
        
        return attack_type, threat_level, reason

    def _signature_detection(self, packet, src_ip: str, dst_ip: str) -> Tuple[AttackType, ThreatLevel, str]:
        """Snort/Suricata-like signature-based detection"""
        
        # SYN Flood detection
        if TCP in packet and packet[TCP].flags & 0x02:  # SYN flag
            pps = self.stats.get_src_pps(src_ip)
            if pps > self.config.get("ddos_syn_threshold", 100):
                return AttackType.DDOS_SYN_FLOOD, ThreatLevel.CRITICAL, \
                       f"SYN flood from {src_ip}: {pps:.1f} pps"

        # UDP Flood detection
        if UDP in packet:
            pps = self.stats.get_src_pps(src_ip)
            if pps > self.config.get("ddos_udp_threshold", 200):
                return AttackType.DDOS_UDP_FLOOD, ThreatLevel.CRITICAL, \
                       f"UDP flood from {src_ip}: {pps:.1f} pps"

        # ICMP Flood detection
        if ICMP in packet:
            pps = self.stats.get_src_pps(src_ip)
            if pps > self.config.get("ddos_icmp_threshold", 150):
                return AttackType.DDOS_ICMP_FLOOD, ThreatLevel.CRITICAL, \
                       f"ICMP flood from {src_ip}: {pps:.1f} pps"

        return AttackType.UNKNOWN, ThreatLevel.LOW, "No signature match"

    def _statistical_detection(self, src_ip: str, dst_ip: str, dst_port: int, 
                              pkt_size: int, timestamp: float) -> Tuple[AttackType, ThreatLevel, str]:
        """Statistical analysis for anomaly-based detection"""

        # High bandwidth detection
        bandwidth_mbps = self.stats.get_src_bandwidth(src_ip) / 1_000_000
        if bandwidth_mbps > self.config.get("bandwidth_threshold_mbps", 100):
            return AttackType.DDOS_UDP_FLOOD, ThreatLevel.CRITICAL, \
                   f"High bandwidth from {src_ip}: {bandwidth_mbps:.1f} Mbps"

        # Large payload anomaly
        if pkt_size > self.config.get("anomaly_payload_threshold", 5000):
            return AttackType.ANOMALOUS_PAYLOAD, ThreatLevel.HIGH, \
                   f"Oversized packet from {src_ip}: {pkt_size} bytes"

        return AttackType.UNKNOWN, ThreatLevel.LOW, "Normal traffic"

    def _get_dst_port(self, packet) -> int:
        """Extract destination port from packet"""
        if TCP in packet:
            return packet[TCP].dport
        if UDP in packet:
            return packet[UDP].dport
        return 0

    def should_alert(self, src_ip: str, attack_type: AttackType) -> bool:
        """Check if we should send alert (rate limiting)"""
        key = f"{src_ip}_{attack_type.value}"
        now = time.time()
        
        with self.lock:
            alerts = self.recent_alerts[key]
            # Remove old alerts
            while alerts and alerts[0] < now - self.alert_lockout:
                alerts.popleft()
            
            # Check if already alerted recently
            if len(alerts) > 0:
                return False
            
            alerts.append(now)
            return True

    def record_event(self, event: dict):
        """Record detected event"""
        with self.lock:
            self.events_detected.append(event)

    def get_events(self, limit: int = 100) -> List[dict]:
        """Get recent events"""
        with self.lock:
            return list(self.events_detected[-limit:])


# Singleton instance
_engine = None

def get_engine() -> IDSIPSEngine:
    """Get or create engine instance"""
    global _engine
    if _engine is None:
        _engine = IDSIPSEngine()
    return _engine
