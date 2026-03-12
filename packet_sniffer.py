from scapy.all import sniff, IP, TCP, UDP
from deploy_firewall import DeployedAIFirewall
import pandas as pd
import time
import os

firewall = DeployedAIFirewall()

LOG_FILE = "firewall_logs.csv"

if not os.path.exists(LOG_FILE):
    df = pd.DataFrame(columns=[
        "timestamp",
        "decision",
        "confidence",
        "anomaly_ratio"
    ])
    df.to_csv(LOG_FILE, index=False)


def process_packet(packet):

    if IP in packet:

        packet_features = {
            "duration": 0,
            "protocol_type": "tcp" if TCP in packet else "udp",
            "service": "http",
            "flag": "SF",
            "src_bytes": len(packet),
            "dst_bytes": len(packet),
            "land": 0,
            "wrong_fragment": 0,
            "urgent": 0
        }

        result = firewall.analyze_packet(packet_features)

        log = {
            "timestamp": time.time(),
            "decision": result["decision"],
            "confidence": result["dnn_confidence"],
            "anomaly_ratio": result["anomaly_ratio"]
        }

        pd.DataFrame([log]).to_csv(LOG_FILE, mode="a", header=False, index=False)

        print("🚨", log)


print("🛡 AI Firewall Live Monitor Started")

sniff(prn=process_packet, store=False)
