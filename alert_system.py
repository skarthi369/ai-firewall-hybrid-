#!/usr/bin/env python3
"""
Production-Grade Alert System
Sends alerts via console, email, Slack, and opens new terminal for critical events
"""

import json
import os
import smtplib
import subprocess
import time
import logging
from collections import deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional
import threading

import requests

logger = logging.getLogger(__name__)

CONFIG_PATH = "alert_config.json"


def _load_config() -> dict:
    """Load alert configuration"""
    if not os.path.exists(CONFIG_PATH):
        return {}
    try:
        with open(CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception as e:
        logger.warning(f"Failed to load config from {CONFIG_PATH}: {e}")
        return {}


def send_email(subject: str, body: str) -> bool:
    """Send email alert"""
    config = _load_config()
    email_cfg = config.get("email", {})
    
    if not email_cfg.get("enabled", False):
        return False

    try:
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = email_cfg.get("from", "firewall@example.com")
        msg['To'] = ", ".join(email_cfg.get("to", []))
        
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(
            email_cfg.get("smtp_server", "smtp.gmail.com"),
            email_cfg.get("smtp_port", 587),
            timeout=10
        ) as smtp:
            smtp.starttls()
            smtp.login(
                email_cfg.get("username", ""),
                email_cfg.get("password", "")
            )
            smtp.send_message(msg)
        logger.debug(f"✉️  Email sent: {subject}")
        return True
    except Exception as e:
        logger.error(f"Email error: {e}")
        return False


def send_slack(message: str) -> bool:
    """Send Slack notification"""
    config = _load_config()
    slack_cfg = config.get("slack", {})
    
    if not slack_cfg.get("enabled", False):
        return False

    url = slack_cfg.get("webhook_url", "")
    if not url:
        return False

    try:
        payload = {"text": message}
        requests.post(url, json=payload, timeout=5)
        logger.debug("📱 Slack sent")
        return True
    except Exception as e:
        logger.error(f"Slack error: {e}")
        return False


class TerminalAlertNotifier:
    """Opens alert messages in a new terminal"""

    @staticmethod
    def notify(title: str, message: str) -> bool:
        """
        Open alert in new terminal window
        Works with common Linux desktop environments
        """
        try:
            # Escape special characters
            msg = message.replace('"', '\\"').replace('$', '\\$')
            
            # Detect desktop environment and open appropriate terminal
            xdg_current = os.environ.get('XDG_CURRENT_DESKTOP', '').lower()
            
            commands = [
                # GNOME Terminal
                f'gnome-terminal -- bash -c "echo \'{title}\\n\\n{msg}\'; read -p \'Press Enter to dismiss...\';"',
                # XFCE Terminal
                f'xfce4-terminal -e "bash -c \\\"echo \\\\\'{title}\\\\n\\\\n{msg}\\\\'; read -p \\\\\'Press Enter to dismiss...\\\\\';\\\""',
                # KDE Konsole
                f'konsole -e "bash -c \\\"echo \\\\\'{title}\\\\n\\\\n{msg}\\\\'; read -p \\\\\'Press Enter to dismiss...\\\\\';\\\""',
                # Fallback: xterm
                f'xterm -hold -e "echo \'{title}\\n\\n{msg}\'; read -p \'Press Enter to dismiss...\''
            ]
            
            for cmd in commands:
                try:
                    subprocess.Popen(cmd, shell=True, 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
                    logger.info(f"🚨 Terminal alert opened: {title}")
                    return True
                except Exception:
                    continue
            
            return False
        except Exception as e:
            logger.error(f"Terminal alert error: {e}")
            return False


class AlertManager:
    """
    Production-grade alert manager with rate limiting and multi-channel delivery
    """

    def __init__(self, alerts_per_minute: int = 10, terminal_alerts: bool = True):
        self.config = _load_config()
        self.alerts_per_minute = alerts_per_minute
        self.terminal_alerts = terminal_alerts
        self.alert_history = deque()
        self.lock = threading.Lock()

    def send_alert(self, title: str, message: str, threat_level: str = "HIGH",
                   open_terminal: bool = False) -> bool:
        """
        Send alert via all enabled channels with rate limiting
        
        Args:
            title: Alert title
            message: Alert message
            threat_level: "LOW", "MEDIUM", "HIGH", "CRITICAL"
            open_terminal: Force terminal notification (overrides settings)
        
        Returns:
            bool: True if alert was sent
        """
        with self.lock:
            now = time.time()
            
            # Rate limiting
            while self.alert_history and self.alert_history[0] < now - 60:
                self.alert_history.popleft()
            
            if len(self.alert_history) >= self.alerts_per_minute:
                logger.warning(f"Alert rate limit exceeded: {title}")
                return False
            
            self.alert_history.append(now)

        # Threat level indicators
        level_emoji = {
            "CRITICAL": "🚨",
            "HIGH": "⚠️ ",
            "MEDIUM": "⏱️ ",
            "LOW": "ℹ️ ",
        }
        emoji = level_emoji.get(threat_level, "📢")

        # Console log (always)
        log_msg = f"{emoji} [{threat_level}] {title}\n{message}"
        if threat_level == "CRITICAL":
            logger.critical(log_msg)
        elif threat_level == "HIGH":
            logger.error(log_msg)
        else:
            logger.warning(log_msg)

        # Prepare alert content
        formatted_msg = f"""
THREAT ALERT - {threat_level}
================================================================================
{title}
================================================================================
{message}
================================================================================
Time: {time.strftime('%Y-%m-%d %H:%M:%S')}
"""

        # Multi-channel delivery
        channels_sent = []

        # Email
        if self.config.get("email", {}).get("enabled"):
            if send_email(f"🔒 IDS/IPS Alert: {title}", formatted_msg):
                channels_sent.append("EMAIL")

        # Slack
        if self.config.get("slack", {}).get("enabled"):
            if send_slack(f"{emoji} {threat_level}: {title}\n{message}"):
                channels_sent.append("SLACK")

        # Terminal notification (for critical threats)
        if (self.terminal_alerts and threat_level == "CRITICAL") or open_terminal:
            if TerminalAlertNotifier.notify(title, message):
                channels_sent.append("TERMINAL")

        # Log delivery
        if channels_sent:
            logger.info(f"✓ Alert delivered via: {', '.join(channels_sent)}")
        else:
            logger.info("✓ Alert logged (no external channels enabled)")

        return True

    def get_alert_count(self) -> int:
        """Get alerts sent in last minute"""
        with self.lock:
            now = time.time()
            while self.alert_history and self.alert_history[0] < now - 60:
                self.alert_history.popleft()
            return len(self.alert_history)


# Singleton instance
_alert_manager = None


def get_alert_manager() -> AlertManager:
    """Get or create alert manager"""
    global _alert_manager
    if _alert_manager is None:
        _alert_manager = AlertManager()
    return _alert_manager
