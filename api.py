import os
import time
import threading
import subprocess
import json

import pandas as pd
from flask import Flask, jsonify, request, render_template_string

from deploy_firewall import DeployedAIFirewall


LOG_FILE = "firewall_logs.csv"

# Ensure log file exists with correct header
if not os.path.exists(LOG_FILE):
    pd.DataFrame(columns=["timestamp", "decision", "confidence", "anomaly_ratio"]).to_csv(LOG_FILE, index=False)

firewall = DeployedAIFirewall()

sniffer_thread = None
sniffer_stop_event = threading.Event()

last_attack_output = ""


def append_log(decision: str, confidence: float, anomaly_ratio: float):
    df = pd.DataFrame([
        {
            "timestamp": time.time(),
            "decision": decision,
            "confidence": confidence,
            "anomaly_ratio": anomaly_ratio,
        }
    ])
    df.to_csv(LOG_FILE, mode="a", header=False, index=False)


def analyze_and_log(packet_features: dict):
    """Analyze one packet and append results to the log."""
    result = firewall.analyze_packet(packet_features)
    append_log(result["decision"], result["dnn_confidence"], result["anomaly_ratio"])
    return result


def _sniffer_process(packet):
    # Minimal feature mapping, similar to packet_sniffer.py
    from scapy.layers.inet import IP, TCP, UDP

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
            "urgent": 0,
        }

        analyze_and_log(packet_features)

    # Stop sniffing if requested
    return sniffer_stop_event.is_set()


def _sniffer_thread():
    from scapy.all import sniff

    # Block until stop event is set
    sniff(prn=_sniffer_process, store=False, stop_filter=lambda pkt: sniffer_stop_event.is_set())


app = Flask(__name__)


@app.route("/")
def index():
    return render_template_string(
        """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AI Firewall Control</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 1.5rem; }
      button { margin: 0.25rem; padding: 0.5rem 1rem; }
      .card { border: 1px solid #ddd; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
      .grid { display: flex; gap: 1rem; flex-wrap: wrap; }
      .grid > div { flex: 1; min-width: 280px; }
      table { width: 100%; border-collapse: collapse; }
      th, td { border: 1px solid #ddd; padding: 0.5rem; text-align: left; }
      th { background: #f4f4f4; }
      pre { background: #111; color: #0f0; padding: 0.5rem; overflow: auto; }
    </style>
  </head>
  <body>
    <h1>🛡 AI Firewall Control</h1>

    <div class="card">
      <h2>Firewall Engine</h2>
      <div class="grid">
        <div>
          <button onclick="fetch('/sniffer/start').then(r => r.json()).then(updateStatus)">Start Sniffer</button>
          <button onclick="fetch('/sniffer/stop').then(r => r.json()).then(updateStatus)">Stop Sniffer</button>
        </div>
        <div>
          <button onclick="fetch('/simulate/normal').then(r => r.json()).then(updateStatus)">Simulate Normal</button>
          <button onclick="fetch('/simulate/suspicious').then(r => r.json()).then(updateStatus)">Simulate Suspicious</button>
        </div>
        <div>
          <select id="attackType">
            <option value="syn">SYN flood (hping3)</option>
            <option value="udp">UDP flood (hping3)</option>
          </select>
          <button onclick="runAttack()">Run Attack Command</button>
        </div>
      </div>

      <p><strong>Sniffer status:</strong> <span id="snifferStatus">unknown</span></p>
      <p><strong>Last action:</strong> <span id="lastAction">none</span></p>
    </div>

    <div class="card">
      <h2>Live Log (last 25 entries)</h2>
      <div id="logTable"></div>
    </div>

    <div class="card">
      <h2>Last Decision</h2>
      <div id="lastDecision" style="font-size:1.2rem; font-weight:700;">(none yet)</div>
    </div>

    <div class="card">
      <h2>Last Attack Output</h2>
      <pre id="attackOutput">(none)</pre>
    </div>

    <script>
      async function fetchStatus() {
        const [snifferResp, logsResp, outputResp] = await Promise.all([
          fetch('/sniffer/status'),
          fetch('/logs'),
          fetch('/attack/output')
        ]);

        const sniffer = await snifferResp.json();
        const logs = await logsResp.json();
        const output = await outputResp.json();

        updateStatus(sniffer);
        renderLogs(logs);
        document.getElementById('attackOutput').textContent = output.output || '(none)';
      }

      function updateStatus(status) {
        document.getElementById('snifferStatus').textContent = status.running ? 'running' : 'stopped';
        document.getElementById('lastAction').textContent = status.message || '—';
      }

      function renderLogs(logs) {
        const rows = logs.map(row => `
          <tr>
            <td>${new Date(row.timestamp * 1000).toLocaleTimeString()}</td>
            <td>${row.decision}</td>
            <td>${row.confidence.toFixed(4)}</td>
            <td>${row.anomaly_ratio.toFixed(4)}</td>
          </tr>
        `).join('\n');

        document.getElementById('logTable').innerHTML = `
          <table>
            <thead><tr><th>Time</th><th>Decision</th><th>Confidence</th><th>Anomaly</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        `;

        const last = logs[logs.length - 1];
        if (last) {
          const decisionEl = document.getElementById('lastDecision');
          decisionEl.textContent = `${last.decision} (conf: ${last.confidence.toFixed(3)}, anomaly: ${last.anomaly_ratio.toFixed(3)})`;
          if (last.decision === 'BLOCK' || last.decision === 'QUARANTINE') {
            decisionEl.style.color = '#c00';
          } else if (last.decision === 'ALLOW') {
            decisionEl.style.color = '#080';
          } else {
            decisionEl.style.color = '#000';
          }
        }
      }

      async function runAttack() {
        const type = document.getElementById('attackType').value;
        const resp = await fetch(`/attack/run?type=${encodeURIComponent(type)}`);
        const data = await resp.json();
        document.getElementById('attackOutput').textContent = data.output || '(none)';
        await fetchStatus();
      }

      setInterval(fetchStatus, 2500);
      fetchStatus();
    </script>
  </body>
</html>
        """
    )


@app.route("/sniffer/status")
def sniffer_status():
    running = sniffer_thread is not None and sniffer_thread.is_alive()
    return jsonify({
        "running": running,
        "message": "sniffer is running" if running else "sniffer is stopped",
    })


@app.route("/sniffer/start")
def start_sniffer():
    global sniffer_thread, sniffer_stop_event

    if sniffer_thread is not None and sniffer_thread.is_alive():
        return jsonify({"running": True, "message": "sniffer already running"})

    sniffer_stop_event.clear()
    sniffer_thread = threading.Thread(target=_sniffer_thread, daemon=True)
    sniffer_thread.start()

    return jsonify({"running": True, "message": "sniffer started"})


@app.route("/sniffer/stop")
def stop_sniffer():
    global sniffer_stop_event

    sniffer_stop_event.set()
    return jsonify({"running": False, "message": "sniffer stop requested"})


@app.route("/logs")
def logs():
    try:
        df = pd.read_csv(LOG_FILE)
        return jsonify(df.tail(25).to_dict(orient="records"))
    except Exception as e:
        return jsonify([])


@app.route("/simulate/normal")
def simulate_normal():
    pkt = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 181,
        "dst_bytes": 5450,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
    }
    result = analyze_and_log(pkt)
    return jsonify({"result": result, "message": "Simulated normal traffic"})


@app.route("/simulate/suspicious")
def simulate_suspicious():
    pkt = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "REJ",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
    }
    result = analyze_and_log(pkt)
    return jsonify({"result": result, "message": "Simulated suspicious traffic"})


@app.route("/attack/run")
def run_attack():
    global last_attack_output

    attack_type = request.args.get("type", "syn")
    # Basic command mapping (requires hping3)
    cmd_map = {
        "syn": ["hping3", "-S", "-p", "80", "-c", "10", "127.0.0.1"],
        "udp": ["hping3", "--udp", "-p", "53", "-c", "10", "127.0.0.1"],
    }

    cmd = cmd_map.get(attack_type)
    if cmd is None:
        last_attack_output = f"Unknown attack type: {attack_type}"
        return jsonify({"output": last_attack_output})

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        last_attack_output = proc.stdout + proc.stderr
    except Exception as e:
        last_attack_output = f"Error running attack command: {e}"

    return jsonify({"output": last_attack_output})


@app.route("/attack/output")
def attack_output():
    return jsonify({"output": last_attack_output})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
