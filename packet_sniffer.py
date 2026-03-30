import os
import time
from collections import deque

import pandas as pd
from scapy.all import sniff, IP, TCP, UDP

from deploy_firewall import DeployedAIFirewall
from nft_utils import ensure_nft_setup, block_ip, list_whitelist_ips
from alerting import AlertManager

# --- Configuration -----------------------------------------------------------
LOG_FILE = "firewall_logs.csv"
BPF_FILTER = "ip and not (src net 127.0.0.0/8 or dst net 127.0.0.0/8)"

# --- Helpers -----------------------------------------------------------------

firewall = DeployedAIFirewall()
ensure_nft_setup()

alert_manager = AlertManager()

# Used for rate calculations
packet_timestamps = deque()
blocked_timestamps = deque()

# Track recent blocked events per IP to label patterns (port scan, large payload, etc.)
ip_block_history = {}

# Keep a small, refreshed whitelisting cache so UI changes are reflected quickly
_whitelist_cache = set()
_last_whitelist_reload = 0

# Expected log schema
LOG_FIELDS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "protocol",
    "src_port",
    "dst_port",
    "src_bytes",
    "dst_bytes",
    "decision",
    "confidence",
    "anomaly_ratio",
    "blocked",
    "event_label",
]


def _ensure_log_header():
    """If the log file exists but has an outdated schema, reset it."""
    if not os.path.exists(LOG_FILE):
        return

    with open(LOG_FILE, "r") as f:
        first = f.readline().strip()

    # If header does not match expected, rotate the file and reset it.
    expected = ",".join(LOG_FIELDS)
    if first != expected:
        backup = LOG_FILE + ".old"
        os.rename(LOG_FILE, backup)
        print(f"⚠️ Log schema changed; rotated old log to {backup}.")
        _log_event({
            "timestamp": time.time(),
            "src_ip": "",
            "dst_ip": "",
            "protocol": "",
            "src_port": "",
            "dst_port": "",
            "src_bytes": 0,
            "dst_bytes": 0,
            "decision": "START",
            "confidence": 0,
            "anomaly_ratio": 0,
            "blocked": False,
            "event_label": "Startup",
        })


def _log_event(event: dict):
    df = pd.DataFrame([event], columns=LOG_FIELDS)
    df.to_csv(LOG_FILE, mode="a", header=not os.path.exists(LOG_FILE), index=False)


def _reload_whitelist_if_needed():
    global _whitelist_cache, _last_whitelist_reload
    if time.time() - _last_whitelist_reload > 5:
        _whitelist_cache = list_whitelist_ips()
        _last_whitelist_reload = time.time()


def _detect_service(packet):
    """Very simple port->service mapping for feature extraction."""
    service_map = {
        80: "http",
        443: "https",
        22: "ssh",
        53: "domain",
        25: "smtp",
        110: "pop3",
        143: "imap",
    }
    try:
        if TCP in packet:
            dport = packet[TCP].dport
            return service_map.get(dport, "other")
        if UDP in packet:
            dport = packet[UDP].dport
            return service_map.get(dport, "other")
    except Exception:
        pass
    return "other"


def _maybe_alert():
    """Send alerts once thresholds are exceeded."""
    now = time.time()

    # Keep only last 60 seconds
    while packet_timestamps and packet_timestamps[0] < now - 60:
        packet_timestamps.popleft()
    while blocked_timestamps and blocked_timestamps[0] < now - 60:
        blocked_timestamps.popleft()

    # Trigger a simple alert when blocks spike
    if len(blocked_timestamps) >= 10:
        alert_manager.send_alert(
            "AI Firewall Alert: High block rate",
            f"Blocked {len(blocked_timestamps)} IPs in the last minute."
        )


def _log_event(event: dict):
    pd.DataFrame([event]).to_csv(LOG_FILE, mode="a", header=not os.path.exists(LOG_FILE), index=False)


# --- Main --------------------------------------------------------------------

_ensure_log_header()


def process_packet(packet):
    if IP not in packet:
        return

    _reload_whitelist_if_needed()

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    # Skip evaluation for whitelisted sources
    if src_ip in _whitelist_cache:
        return

    src_port = None
    dst_port = None
    proto = "tcp" if TCP in packet else "udp" if UDP in packet else str(packet[IP].proto)

    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flag = packet[TCP].flags
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        flag = ""  # UDP has no TCP flags
    else:
        flag = ""

    packet_features = {
        "duration": 0,
        "protocol_type": proto,
        "service": _detect_service(packet),
        "flag": str(flag),
        "src_bytes": len(packet),
        "dst_bytes": len(packet),
        "land": 1 if src_ip == dst_ip else 0,
        "wrong_fragment": 0,
        "urgent": 0,
    }

    result = firewall.analyze_packet(packet_features)

    is_blocked = False
    if result["decision"] == "BLOCK":
        is_blocked = block_ip(src_ip)
        blocked_timestamps.append(time.time())

    now = time.time()
    packet_timestamps.append(now)

    # Label the event for dashboard messaging
    # Rapid repeated blocks from the same IP suggest a port scan/scan attempt
    history = ip_block_history.setdefault(src_ip, deque())
    history.append(now)
    while history and history[0] < now - 15:
        history.popleft()

    if len(history) >= 6:
        event_label = "Possible port scan detected"
    elif packet_features["src_bytes"] > 12000 or packet_features["dst_bytes"] > 12000:
        event_label = "Large packet / high bandwidth detected"
    elif result["decision"] == "QUARANTINE":
        event_label = "Unusual traffic detected"
    else:
        event_label = "Normal"

    _maybe_alert()

    log = {
        "timestamp": now,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_bytes": packet_features["src_bytes"],
        "dst_bytes": packet_features["dst_bytes"],
        "decision": result["decision"],
        "confidence": result["dnn_confidence"],
        "anomaly_ratio": result["anomaly_ratio"],
        "blocked": is_blocked,
        "event_label": event_label,
    }

    _log_event(log)
    print("🚨", log)


print("🛡 AI Firewall Live Monitor Started")
print("➡️  Make sure to run as root if you want nftables auto-blocking enabled")

sniff(prn=process_packet, store=False, filter=BPF_FILTER)
