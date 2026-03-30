# AI Hybrid Firewall

AI-powered hybrid firewall with packet sniffing, DL-based threat detection, and SOC dashboard. 

## Features
- Real-time packet monitoring
- Machine learning threat detection
- SOC dashboard visualization
- Firewall rule automation

## Technologies
- Python
- Scikit-learn
- Flask
- Packet sniffing

## Project Structure
app.py - Main application (file-based traffic analyzer)
packet_sniffer.py - Network packet monitoring & live decision logging
soc_dashboard.py - SOC visualization dashboard (reads logs)
deploy_firewall.py - Firewall model deployment and inference

## Getting Started (Real-Time Monitoring)

### 1) Activate the Python environment

```bash
source firewall_env/bin/activate
```

### 2) Start the packet sniffer (requires root / raw sockets)

This runs the AI detection engine and streams results into `firewall_logs.csv`.

**Important:** When using `sudo`, the virtual environment is not automatically applied, which can cause module import errors (like `tensorflow`). Use one of these methods:

```bash
# Option A: preserve your venv environment
sudo -E $(which python) packet_sniffer.py

# Option B: run as your venv python explicitly
sudo env "PATH=$PATH" $(which python) packet_sniffer.py
```

Alternatively, if you don’t want to run as root, you can grant raw-socket permission to your Python binary (Linux only):

```bash
sudo setcap cap_net_raw+ep "$(which python)"
```

*The sniffer uses nftables for blocking and will only actually block when run as root.*

### 3) Start the SOC dashboard

```bash
streamlit run soc_dashboard.py
```

This dashboard shows live metrics, recent events, and provides **blocklist / whitelist controls**.

### 4) (Optional) Analyze offline traffic via CSV

```bash
streamlit run app.py
```
### 5) Generate test attack traffic (port scans, large packets, etc.)

To help validate detection/blocking behavior, run the built-in attack generator:

```bash
python attack_generator.py --mode portscan --target 127.0.0.1 --start-port 1 --end-port 200 --count 100
```

Other modes:

```bash
python attack_generator.py --mode large --target 127.0.0.1 --port 80 --count 10 --size 15000
python attack_generator.py --mode udpflood --target 127.0.0.1 --port 53 --count 100
```
---

## key capabilities in this repository

✅ **Real-time analysis:** packet capture + AI model evaluation + logging

✅ **Dynamic blocking:** nftables blocklists (not iptables)

✅ **Dashboard:** live metrics, recent events, and blocklist/whitelist controls

✅ **Alerts:** email/Slack alerts when limits are exceeded (configurable in `alert_config.json`)

---

## Advanced integration (Suricata + ELK)

This project is designed to be extended with real IDS/IPS and log ingestion pipelines.

### 1) Run Suricata in IPS mode

Install Suricata (Ubuntu/Debian example):

```bash
sudo apt update
sudo apt install suricata
```

Enable IPS mode by creating a yaml policy and running Suricata with `--af-packet`.

Then configure `eve.json` output in `/etc/suricata/suricata.yaml`, e.g.:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - tls
```

You can then ingest `eve.json` into ELK using Filebeat or Logstash.

The repository includes `suricata_ingest.py`, which can tail `eve.json` and turn Suricata alerts into a CSV that the dashboard can show:

```bash
python suricata_ingest.py
```

### 2) Ship logs into ELK (Elastic Stack)

A minimal Filebeat configuration (`filebeat.yml`) can tail `firewall_logs.csv` and Suricata's `eve.json`, then send to Elasticsearch:

```yaml
filebeat.inputs:
- type: log
  paths:
    - "/path/to/AI_Firewall_Project/firewall_logs.csv"
    - "/var/log/suricata/eve.json"
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
```

### 3) Dashboards

You can build Kibana dashboards for:
- blocked IPs over time (with unblock controls in the dashboard)
- Suricata alert types (DDoS, port scan, SQLi, etc.)
- bandwidth and top talkers

---

## Alerting

Configure `alert_config.json` to send email or Slack notifications when thresholds are exceeded. The default config is disabled; update credentials and enable `enabled: true`.

---

## Notes

- **Whitelist** entries always bypass blocking.
- **Blacklist** entries are added to nftables and saved to `blocked_ips.txt`.
- The system is built as a PoC; in production, use proper hardening, logging, and secure credential storage.
