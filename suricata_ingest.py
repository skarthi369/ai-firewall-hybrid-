import json
import os
import time

EVE_LOG = "/var/log/suricata/eve.json"
OUTPUT_CSV = "suricata_alerts.csv"


def _ensure_csv():
    if not os.path.exists(OUTPUT_CSV):
        with open(OUTPUT_CSV, "w") as f:
            f.write("timestamp,src_ip,dst_ip,proto,event,signature,category\n")


def _parse_line(line: str):
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        return None


def tail_file(path, sleep=1.0):
    with open(path, "r") as f:
        # Seek to end
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(sleep)
                continue
            yield line


def run():
    if not os.path.exists(EVE_LOG):
        print(f"Suricata log not found: {EVE_LOG}")
        return

    _ensure_csv()

    for line in tail_file(EVE_LOG, sleep=0.5):
        data = _parse_line(line)
        if not data:
            continue

        # Only interested in alert events for this PoC
        if data.get("event_type") != "alert":
            continue

        ts = data.get("timestamp", "")
        src = data.get("src_ip", "")
        dst = data.get("dest_ip", "")
        proto = data.get("proto", "")
        sig = data.get("alert", {}).get("signature", "")
        cat = data.get("alert", {}).get("category", "")

        with open(OUTPUT_CSV, "a") as f:
            f.write(f"{ts},{src},{dst},{proto},alert,{sig},{cat}\n")


if __name__ == "__main__":
    run()
