import os
import subprocess
import json

# NOTE: nftables operations require root privileges.
# This module provides a simple wrapper for building a lightweight
# packet-filtering table with a blocklist/whitelist.

TABLE_NAME = "ai_firewall"
CHAIN_NAME = "input"
SET_BLOCK = "blocked_ips"
SET_WHITELIST = "whitelist_ips"

BLOCKLIST_FILE = "blocked_ips.txt"
WHITELIST_FILE = "whitelist_ips.txt"

DEFAULT_RULES = [
    # Accept traffic from whitelist first
    f"add rule inet {TABLE_NAME} {CHAIN_NAME} ip saddr @{SET_WHITELIST} accept",
    # Drop traffic from blocked set
    f"add rule inet {TABLE_NAME} {CHAIN_NAME} ip saddr @{SET_BLOCK} drop",
]


def _run_nft(cmd: str):
    try:
        completed = subprocess.run(
            ["nft"] + cmd.split(),
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout
    except FileNotFoundError:
        raise RuntimeError("nft command not found; please install nftables")
    except subprocess.CalledProcessError as e:
        # If error contains "exists" or "already", ignore it for idempotency
        if "exists" in e.stderr or "already" in e.stderr:
            return e.stderr
        raise


def ensure_nft_setup():
    """Ensure the nftables table/chain/sets exist, and base rules are installed."""

    try:
        _run_nft(f"add table inet {TABLE_NAME}")
    except RuntimeError:
        raise
    except Exception:
        pass

    try:
        _run_nft(
            f"add chain inet {TABLE_NAME} {CHAIN_NAME} {{ type filter hook input priority 0 ; policy accept }}"
        )
    except Exception:
        pass

    try:
        _run_nft(f"add set inet {TABLE_NAME} {SET_BLOCK} {{ type ipv4_addr ; flags interval ; }}")
    except Exception:
        pass

    try:
        _run_nft(f"add set inet {TABLE_NAME} {SET_WHITELIST} {{ type ipv4_addr ; flags interval ; }}")
    except Exception:
        pass

    # Ensure rules exist (non-fatal if they already exist)
    for rule in DEFAULT_RULES:
        try:
            _run_nft(rule)
        except Exception:
            pass


def _load_ips(path: str):
    if not os.path.exists(path):
        return set()
    with open(path, "r") as f:
        return {line.strip() for line in f if line.strip()}


def _save_ip(path: str, ip: str):
    with open(path, "a") as f:
        f.write(f"{ip}\n")


def _write_ips(path: str, ips):
    with open(path, "w") as f:
        for ip in sorted(ips):
            f.write(f"{ip}\n")


def list_blocked_ips():
    return _load_ips(BLOCKLIST_FILE)


def list_whitelist_ips():
    return _load_ips(WHITELIST_FILE)


def block_ip(ip: str):
    """Block an IP at nftables level and persist it."""

    if ip in list_blocked_ips():
        return False

    # persist on disk
    _save_ip(BLOCKLIST_FILE, ip)

    # apply to nftables
    if os.geteuid() != 0:
        return False

    try:
        _run_nft(f"add element inet {TABLE_NAME} {SET_BLOCK} {{ {ip} }}")
        return True
    except Exception:
        return False


def unblock_ip(ip: str):
    """Remove an IP from the blocklist."""
    blocked = list_blocked_ips()
    if ip not in blocked:
        return False

    blocked.remove(ip)
    _write_ips(BLOCKLIST_FILE, blocked)

    if os.geteuid() != 0:
        return False

    try:
        _run_nft(f"delete element inet {TABLE_NAME} {SET_BLOCK} {{ {ip} }}")
        return True
    except Exception:
        return False


def whitelist_ip(ip: str):
    """Whitelist an IP so it is accepted before block rules."""
    if ip in list_whitelist_ips():
        return False

    _save_ip(WHITELIST_FILE, ip)

    if os.geteuid() != 0:
        return False

    try:
        _run_nft(f"add element inet {TABLE_NAME} {SET_WHITELIST} {{ {ip} }}")
        return True
    except Exception:
        return False


def remove_whitelist_ip(ip: str):
    whitelisted = list_whitelist_ips()
    if ip not in whitelisted:
        return False

    whitelisted.remove(ip)
    _write_ips(WHITELIST_FILE, whitelisted)

    if os.geteuid() != 0:
        return False

    try:
        _run_nft(f"delete element inet {TABLE_NAME} {SET_WHITELIST} {{ {ip} }}")
        return True
    except Exception:
        return False
