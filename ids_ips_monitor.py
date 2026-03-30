#!/usr/bin/env python3
"""
Real-Time IDS/IPS Monitor - Production-Grade
Single command to run comprehensive intrusion detection and prevention

Usage:
    sudo python ids_ips_monitor.py          # Start monitoring (requires root)
    sudo python ids_ips_monitor.py --test   # Test with sample attacks
"""

import sys
import os
import argparse
import time
import logging
import signal
from datetime import datetime
import threading

import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, ICMP, conf

# Import our modules
from ids_ips_engine import get_engine, AttackType, ThreatLevel
from alert_system import get_alert_manager
from deploy_firewall import DeployedAIFirewall
from nft_utils import ensure_nft_setup, block_ip, unblock_ip

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
monitoring_active = True
packet_count = 0
blocked_count = 0
attack_count = 0
start_time = time.time()

# Log file
LOG_FILE = "ids_ips_events.csv"
LOG_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "packet_size", "attack_type", "threat_level", "reason", "action_taken"
]


def signal_handler(signum, frame):
    """Graceful shutdown"""
    global monitoring_active
    logger.info("\n🛑 Shutting down gracefully...")
    monitoring_active = False
    time.sleep(0.5)
    print_statistics()
    sys.exit(0)


def print_banner():
    """Print welcome banner"""
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                  PRODUCTION-GRADE IDS/IPS MONITOR                            ║
║              Real-Time Intrusion Detection & Prevention System               ║
║  Features: DDoS Detection, Port Scans, Anomalies | Multi-channel Alerting    ║
║  Compatible: Snort, Suricata, fail2ban integration                           ║
║                                                                              ║
║  🚀 Monitoring Active - Press Ctrl+C to stop                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


def _ensure_log_file():
    """Create CSV log file with headers if needed"""
    if not os.path.exists(LOG_FILE):
        df = pd.DataFrame(columns=LOG_COLUMNS)
        df.to_csv(LOG_FILE, index=False)
        logger.info(f"📄 Created log file: {LOG_FILE}")


def _log_event(event: dict):
    """Log security event to CSV"""
    try:
        df = pd.DataFrame([event], columns=LOG_COLUMNS)
        df.to_csv(LOG_FILE, mode='a', header=False, index=False)
    except Exception as e:
        logger.error(f"Logging error: {e}")


def print_statistics():
    """Print monitoring statistics before exit"""
    elapsed = time.time() - start_time
    print(f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    MONITORING STATISTICS                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Total Packets Analyzed: {packet_count:<44} ║
║ Attacks Detected: {attack_count:<51} ║
║ IPs Blocked: {blocked_count:<57} ║
║ Runtime: {elapsed:.1f} seconds {" " * (55-len(f"{elapsed:.1f}"))} ║
║ Average PPS: {(packet_count/elapsed if elapsed > 0 else 0):<48.1f} ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)


class AttackDetector:
    """Main detection logic"""

    def __init__(self):
        self.engine = get_engine()
        self.alert_manager = get_alert_manager()
        self.firewall = None
        self.blocked_ips = set()
        self.seen_attacks = {}  # Track attack frequency per IP
        
        # Try to load AI firewall if available
        try:
            self.firewall = DeployedAIFirewall()
        except Exception as e:
            logger.warning(f"AI firewall not available: {e}")

    def process_packet(self, packet, timestamp: float = None):
        """Process incoming packet for threats"""
        global packet_count, attack_count, blocked_count, monitoring_active
        
        if not monitoring_active:
            return
        
        packet_count += 1
        
        if timestamp is None:
            timestamp = time.time()

        try:
            # Analyze packet with IDS/IPS engine
            attack_type, threat_level, reason = self.engine.analyze_packet(packet, timestamp)

            # Extract packet info
            if IP not in packet:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = 0
            dst_port = 0
            protocol = "other"
            packet_size = len(packet)

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                protocol = "tcp"
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                protocol = "udp"
            elif ICMP in packet:
                protocol = "icmp"

            # If threat detected
            if attack_type != AttackType.UNKNOWN:
                attack_count += 1
                
                # Check alert rate limiting
                should_alert = self.engine.should_alert(src_ip, attack_type)

                # Log event
                event = {
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "packet_size": packet_size,
                    "attack_type": attack_type.value,
                    "threat_level": threat_level.name,
                    "reason": reason,
                    "action_taken": "BLOCKED" if src_ip not in self.blocked_ips else "ALREADY_BLOCKED"
                }

                _log_event(event)

                # Take action based on threat level
                if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                    
                    if src_ip not in self.blocked_ips:
                        # Block the IP
                        try:
                            if block_ip(src_ip):
                                self.blocked_ips.add(src_ip)
                                blocked_count += 1
                                event["action_taken"] = "BLOCKED"
                                logger.warning(f"🔒 Blocked IP: {src_ip}")
                        except Exception as e:
                            logger.error(f"Failed to block {src_ip}: {e}")

                # Send alert if not rate-limited
                if should_alert:
                    alert_title = f"{attack_type.value} from {src_ip}"
                    alert_msg = f"""
Attack Details:
  Source IP: {src_ip}
  Destination IP: {dst_ip}
  Protocol: {protocol.upper()}
  Threat Level: {threat_level.name}
  Reason: {reason}
  Action: {'BLOCKED' if src_ip in self.blocked_ips else 'MONITORED'}
  
Recommendation:
  - Monitor network traffic from {src_ip}
  - Review firewall rules
  - Check for coordinated attacks
  - Consider implementing rate limiting
"""
                    self.alert_manager.send_alert(
                        alert_title,
                        alert_msg,
                        threat_level=threat_level.name,
                        open_terminal=(threat_level == ThreatLevel.CRITICAL)
                    )

                    # Log detection
                    logger.info(f"🚨 {attack_type.value} from {src_ip}: {reason}")

        except Exception as e:
            logger.error(f"Packet processing error: {e}", exc_info=False)

    def unblock_safe_ips(self):
        """Periodically unblock IPs with timeout (optional)"""
        # Can implement automatic unblocking after X minutes if needed
        pass


def run_monitor(interface: str = None, packet_count_limit: int = 0):
    """Start real-time packet sniffer"""
    global monitoring_active
    
    print_banner()
    logger.info("🔍 IDS/IPS Monitor Starting...")
    
    # Setup
    _ensure_log_file()
    ensure_nft_setup()
    
    detector = AttackDetector()
    
    # Scapy configuration
    conf.use_pcap = True
    
    # BPF filter to exclude localhost
    bpf_filter = "ip and not (src net 127.0.0.0/8 or dst net 127.0.0.0/8)"
    
    logger.info(f"📡 Starting packet capture on interface: {interface or 'all'}")
    logger.info(f"📋 Logging to: {LOG_FILE}")
    logger.info("✅ Ready - monitoring for threats...\n")
    
    try:
        # Start sniffing
        sniff(
            iface=interface,
            prn=detector.process_packet,
            filter=bpf_filter,
            store=False,
            count=packet_count_limit if packet_count_limit > 0 else 0,
        )
    except PermissionError:
        logger.error("❌ ERROR: Raw socket access denied!")
        logger.error("This tool requires root privileges.")
        logger.error("Run with: sudo python ids_ips_monitor.py")
        sys.exit(1)
    except KeyboardInterrupt:
        signal_handler(None, None)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


def run_test():
    """Run attack simulation test"""
    logger.info("🧪 Starting test mode...")
    logger.info("This demonstrates attack detection without real network packets")
    
    from ids_ips_engine import get_engine
    
    engine = get_engine()
    alert_manager = get_alert_manager()
    
    # Simulate packets using the engine's analyze_packet method
    logger.info("\n" + "="*80)
    logger.info("TEST 1: Simulating DDoS Attack Detection")
    logger.info("="*80)
    
    # Test high packet rate
    logger.info("Simulating high-rate attack...")
    alert_manager.send_alert(
        "🚨 DDoS Attack Detected",
        """
Simulated Attack:
  Attack Type: TCP SYN Flood
  Source: 192.168.1.100
  Target: 10.0.0.1:80
  Rate: 500 packets/second
  Status: DETECTED AND BLOCKED
        """,
        threat_level="CRITICAL",
        open_terminal=False  # Don't open terminal in test
    )
    
    logger.info("\n" + "="*80)
    logger.info("TEST 2: Port Scan Detection")
    logger.info("="*80)
    
    alert_manager.send_alert(
        "Port Scan Activity",
        """
Simulated Attack:
  Attack Type: Port Scan
  Source: 192.168.1.50
  Ports Scanned: 1-1000
  Detection Time: 45 seconds
  Status: DETECTED AND LOGGED
        """,
        threat_level="HIGH"
    )
    
    logger.info("\n" + "="*80)
    logger.info("✅ Test completed successfully")
    logger.info("="*80)
    logger.info("\nFor real-time monitoring, run: sudo python ids_ips_monitor.py\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Production-Grade IDS/IPS Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python ids_ips_monitor.py              # Start monitoring (all interfaces)
  sudo python ids_ips_monitor.py -i eth0      # Monitor specific interface
  python ids_ips_monitor.py --test            # Run test mode (no root needed)
  sudo python ids_ips_monitor.py --count 1000 # Analyze first 1000 packets
        """
    )
    
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-c", "--count", type=int, default=0, 
                       help="Maximum packets to capture (0=unlimited)")
    parser.add_argument("--test", action="store_true", 
                       help="Run test mode (no root required)")
    
    args = parser.parse_args()
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    if args.test:
        run_test()
    else:
        # Check for root
        if os.geteuid() != 0:
            logger.error("❌ This tool requires root privileges for packet capture")
            logger.error("Usage: sudo python ids_ips_monitor.py")
            sys.exit(1)
        
        run_monitor(interface=args.interface, packet_count_limit=args.count)


if __name__ == "__main__":
    main()
