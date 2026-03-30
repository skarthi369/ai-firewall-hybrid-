import json
import os
import smtplib
import time
from collections import deque
from email.message import EmailMessage

import requests

CONFIG_PATH = "alert_config.json"


def _load_config():
    if not os.path.exists(CONFIG_PATH):
        return None
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


def send_email(subject: str, body: str):
    config = _load_config()
    if not config or not config.get("email", {}).get("enabled"):
        return False

    email_cfg = config["email"]
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = email_cfg.get("from")
    msg["To"] = ",".join(email_cfg.get("to", []))
    msg.set_content(body)

    try:
        with smtplib.SMTP(email_cfg.get("smtp_server"), email_cfg.get("smtp_port")) as smtp:
            smtp.starttls()
            smtp.login(email_cfg.get("username"), email_cfg.get("password"))
            smtp.send_message(msg)
        return True
    except Exception:
        return False


def send_slack(message: str):
    config = _load_config()
    if not config or not config.get("slack", {}).get("enabled"):
        return False

    url = config["slack"].get("webhook_url")
    if not url:
        return False

    try:
        requests.post(url, json={"text": message}, timeout=5)
        return True
    except Exception:
        return False


class AlertManager:
    def __init__(self):
        self.config = _load_config() or {}
        self.alerts_sent = deque()

    def _send(self, title: str, message: str):
        slack_ok = send_slack(f"{title}\n{message}")
        email_ok = send_email(title, message)
        return slack_ok or email_ok

    def send_alert(self, title: str, message: str):
        # Rate limit alerts to configured threshold
        thresholds = self.config.get("thresholds", {})
        per_min = thresholds.get("alerts_per_minute", 5)
        now = time.time()
        # remove old
        while self.alerts_sent and self.alerts_sent[0] < now - 60:
            self.alerts_sent.popleft()
        if len(self.alerts_sent) >= per_min:
            return False
        if self._send(title, message):
            self.alerts_sent.append(now)
            return True
        return False
