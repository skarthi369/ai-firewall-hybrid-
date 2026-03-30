import argparse
import random
import time
import sys
import os

from scapy.all import IP, TCP, UDP, send, conf


def port_scan(target: str, start_port: int, end_port: int, count: int, delay: float):
    print(f"[*] Port scan {target}:{start_port}-{end_port} ({count} packets)")
    ports = list(range(start_port, end_port + 1))
    try:
        for i in range(count):
            port = random.choice(ports)
            pkt = IP(dst=target) / TCP(dport=port, flags="S")
            send(pkt, verbose=False)
            if (i + 1) % 50 == 0:
                print(f"  [{i+1}/{count}] packets sent")
            time.sleep(delay)
        print("[+] Port scan completed")
    except PermissionError:
        print("\n❌ ERROR: Raw socket access denied!")
        print("⚠️  Attack generator requires root privileges to send raw packets.")
        print("\n✅ Fix: Run with sudo:")
        print("   sudo python attack_generator.py --mode portscan --count 300")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during port scan: {e}")
        sys.exit(1)


def large_payload(target: str, port: int, size: int, count: int, delay: float):
    print(f"[*] Sending {count} large packets ({size} bytes) to {target}:{port}")
    payload = b"A" * size
    try:
        for i in range(count):
            pkt = IP(dst=target) / TCP(dport=port, flags="PA") / payload
            send(pkt, verbose=False)
            if (i + 1) % 10 == 0:
                print(f"  [{i+1}/{count}] packets sent")
            time.sleep(delay)
        print("[+] Large payload traffic completed")
    except PermissionError:
        print("\n❌ ERROR: Raw socket access denied!")
        print("⚠️  Attack generator requires root privileges to send raw packets.")
        print("\n✅ Fix: Run with sudo:")
        print("   sudo python attack_generator.py --mode large --count 50 --size 20000")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error sending large payloads: {e}")
        sys.exit(1)


def udp_flood(target: str, port: int, count: int, delay: float):
    print(f"[*] UDP flood to {target}:{port} ({count} packets)")
    try:
        for i in range(count):
            pkt = IP(dst=target) / UDP(dport=port) / (b"X" * 1024)
            send(pkt, verbose=False)
            if (i + 1) % 100 == 0:
                print(f"  [{i+1}/{count}] packets sent")
            time.sleep(delay)
        print("[+] UDP flood completed")
    except PermissionError:
        print("\n❌ ERROR: Raw socket access denied!")
        print("⚠️  Attack generator requires root privileges to send raw packets.")
        print("\n✅ Fix: Run with sudo:")
        print("   sudo python attack_generator.py --mode udpflood --count 200")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during UDP flood: {e}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Attack traffic generator for AI firewall testing")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname")
    parser.add_argument("--mode", choices=["portscan", "large", "udpflood"], default="portscan")
    parser.add_argument("--start-port", type=int, default=1, help="Start port (for portscan)")
    parser.add_argument("--end-port", type=int, default=200, help="End port (for portscan)")
    parser.add_argument("--port", type=int, default=80, help="Destination port (for large/udp)")
    parser.add_argument("--count", type=int, default=100, help="Number of packets to send")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets (seconds)")
    parser.add_argument("--size", type=int, default=15000, help="Payload size for large packet test")

    args = parser.parse_args()

    # Check if running as root
    if os.geteuid() != 0:
        print("⚠️  WARNING: This script should be run with sudo for best results.")
        print("   Some systems may still block raw packet sending without root.\n")

    if args.mode == "portscan":
        port_scan(args.target, args.start_port, args.end_port, args.count, args.delay)
    elif args.mode == "large":
        large_payload(args.target, args.port, args.size, args.count, args.delay)
    elif args.mode == "udpflood":
        udp_flood(args.target, args.port, args.count, args.delay)


if __name__ == "__main__":
    main()
