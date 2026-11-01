"""
Mini-SOC SOAR Notification Dispatcher
Sends formatted alerts to Slack/Discord/Webhooks or logs formatted messages.
"""

import os
import logging
import json
import urllib.request
from typing import Dict, Any, Optional

logger = logging.getLogger("soar.notifier")


class Notifier:
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("SOAR_SLACK_WEBHOOK_URL", "")

    def send_incident_alert(self, alert_data: Dict[str, Any], action_taken: str, details: str) -> bool:
        src_ip = alert_data.get("src_ip", "Unknown")
        signature = alert_data.get("signature", "Unknown Signature")
        mitre_tech = alert_data.get("mitre_technique_id", "N/A")
        mitre_name = alert_data.get("mitre_technique_name", "N/A")
        severity = alert_data.get("severity", "HIGH").upper()

        text_message = (
            f"🚨 *[Mini-SOC Automated Defense Alert]*\n"
            f"• *Severity:* {severity}\n"
            f"• *Detection:* {signature} (SID: {alert_data.get('signature_id')})\n"
            f"• *MITRE ATT&CK:* {mitre_tech} - {mitre_name}\n"
            f"• *Attacker IP:* `{src_ip}`\n"
            f"• *Automated Response:* *{action_taken}*\n"
            f"• *Action Summary:* {details}"
        )

        logger.info(f"[NOTIFIER] Alert dispatched for {src_ip} -> {action_taken}")

        if not self.webhook_url:
            logger.info(f"[SLACK SIMULATOR] Notification payload:\n{text_message}")
            return True

        try:
            payload = json.dumps({"text": text_message}).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                return response.status in (200, 204)
        except Exception as e:
            logger.error(f"[NOTIFIER] Error sending webhook: {e}")
            return False
