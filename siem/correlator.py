"""
Mini-SOC SIEM Correlation Engine & MITRE ATT&CK Mapper
Correlates low-level Suricata events, identifies attack patterns using sliding windows,
maps detections to the MITRE ATT&CK framework, and dispatches webhooks to SOAR.
"""

import time
import json
import logging
import urllib.request
import os
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger("siem.correlator")

# MITRE ATT&CK Mapping Registry
MITRE_TECHNIQUE_MAP = {
    1000001: {"id": "T1046", "name": "Network Service Scanning", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "HIGH"},
    1000002: {"id": "T1046", "name": "Network Service Scanning", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "HIGH"},
    1000003: {"id": "T1046", "name": "Network Service Scanning", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "HIGH"},
    1000004: {"id": "T1046", "name": "Network Service Scanning", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "HIGH"},
    1000005: {"id": "T1046", "name": "Network Service Scanning", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "HIGH"},
    1000010: {"id": "T1110.001", "name": "Password Guessing", "tactic_id": "TA0006", "tactic_name": "Credential Access", "severity": "CRITICAL"},
    1000011: {"id": "T1110.001", "name": "Password Guessing", "tactic_id": "TA0006", "tactic_name": "Credential Access", "severity": "CRITICAL"},
    1000020: {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic_id": "TA0001", "tactic_name": "Initial Access", "severity": "HIGH"},
    1000021: {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic_id": "TA0001", "tactic_name": "Initial Access", "severity": "HIGH"},
    1000022: {"id": "T1083", "name": "File and Directory Discovery", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "HIGH"},
    1000023: {"id": "T1083", "name": "File and Directory Discovery", "tactic_id": "TA0007", "tactic_name": "Discovery", "severity": "MEDIUM"},
    1000030: {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic_id": "TA0002", "tactic_name": "Execution", "severity": "CRITICAL"},
    1000031: {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic_id": "TA0001", "tactic_name": "Initial Access", "severity": "CRITICAL"},
    1000040: {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic_id": "TA0043", "tactic_name": "Reconnaissance", "severity": "MEDIUM"},
    1000041: {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic_id": "TA0043", "tactic_name": "Reconnaissance", "severity": "HIGH"},
    1000042: {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic_id": "TA0043", "tactic_name": "Reconnaissance", "severity": "MEDIUM"},
    1000050: {"id": "T1595", "name": "Active Scanning (Benign Audit)", "tactic_id": "TA0043", "tactic_name": "Reconnaissance", "severity": "LOW"},
}


class SIEMCorrelationEngine:
    def __init__(self, soar_webhook_url: str = "http://localhost:8001/soar/webhook",
                 soar_secret: str = "mini-soc-secure-webhook-token-2026"):
        self.soar_webhook_url = soar_webhook_url
        self.soar_secret = soar_secret
        
        # Sliding window correlation caches: key -> deque of timestamps
        # Sliding window: (src_ip, alert_type) -> deque of alert timestamps
        self.sliding_windows = defaultdict(lambda: deque())
        
        # In-memory storage for SOC dashboard
        self.raw_alerts: List[Dict[str, Any]] = []
        self.incidents: List[Dict[str, Any]] = []
        self.mitre_stats = defaultdict(int)

    def enrich_alert(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalizes raw Suricata eve.json alert or custom alert into standard SIEM schema
        and maps it to MITRE ATT&CK.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        
        # Suricata eve.json format handling
        if "alert" in raw_event:
            alert_obj = raw_event["alert"]
            sig_id = alert_obj.get("signature_id", 0)
            signature = alert_obj.get("signature", "Unknown Signature")
            src_ip = raw_event.get("src_ip", "0.0.0.0")
            src_port = raw_event.get("src_port", 0)
            dest_ip = raw_event.get("dest_ip", "0.0.0.0")
            dest_port = raw_event.get("dest_port", 0)
            proto = raw_event.get("proto", "TCP")
            timestamp = raw_event.get("timestamp", now_iso)
        else:
            # Direct normalized format
            sig_id = raw_event.get("signature_id", 0)
            signature = raw_event.get("signature", "Unknown Signature")
            src_ip = raw_event.get("src_ip", "0.0.0.0")
            src_port = raw_event.get("src_port", 0)
            dest_ip = raw_event.get("dest_ip", "0.0.0.0")
            dest_port = raw_event.get("dest_port", 0)
            proto = raw_event.get("proto", "TCP")
            timestamp = raw_event.get("timestamp", now_iso)

        mitre_info = MITRE_TECHNIQUE_MAP.get(sig_id, {
            "id": "T1046" if "scan" in signature.lower() else "T1190",
            "name": "General Exploitation/Recon",
            "tactic_id": "TA0007",
            "tactic_name": "Discovery",
            "severity": "MEDIUM"
        })

        alert_id = f"ALT-{int(time.time() * 1000)}-{sig_id}"

        enriched = {
            "id": alert_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "proto": proto,
            "signature": signature,
            "signature_id": sig_id,
            "severity": mitre_info["severity"],
            "mitre_technique_id": mitre_info["id"],
            "mitre_technique_name": mitre_info["name"],
            "mitre_tactic_id": mitre_info["tactic_id"],
            "mitre_tactic_name": mitre_info["tactic_name"],
            "raw_payload": raw_event
        }

        return enriched

    def process_event(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main pipeline: Ingest -> Enrich -> Correlate -> SOAR Webhook Trigger
        """
        enriched_alert = self.enrich_alert(raw_event)
        self.raw_alerts.insert(0, enriched_alert)
        # Cap raw alerts buffer
        if len(self.raw_alerts) > 2000:
            self.raw_alerts.pop()

        # Update MITRE stats
        tech_id = enriched_alert["mitre_technique_id"]
        if tech_id:
            self.mitre_stats[tech_id] += 1

        # Check correlation logic
        correlated_incident = self._evaluate_correlation(enriched_alert)

        # Dispatch alert to SOAR webhook
        soar_response = self._dispatch_to_soar(enriched_alert)

        return {
            "alert": enriched_alert,
            "correlated_incident": correlated_incident,
            "soar_response": soar_response
        }

    def _evaluate_correlation(self, alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Sliding-window event correlation:
        Aggregates individual alerts into high-confidence incidents.
        Example: 5+ failed attempts from same IP within 60 seconds.
        """
        src_ip = alert["src_ip"]
        tech_id = alert["mitre_technique_id"]
        now = time.time()

        key = (src_ip, tech_id)
        window = self.sliding_windows[key]

        # Prune events older than 60 seconds
        while window and (now - window[0]) > 60:
            window.popleft()

        window.append(now)
        count = len(window)

        # Thresholds for generating a Correlated Incident
        threshold = 5 if tech_id in ("T1110.001", "T1046") else 3

        if count >= threshold:
            # Check if we already have an active incident for this key in the last 60 seconds
            incident_id = f"INC-{src_ip}-{tech_id}"
            existing = next((inc for inc in self.incidents if inc["id"] == incident_id and (now - inc["last_seen_epoch"]) < 60), None)

            if existing:
                existing["event_count"] = count
                existing["last_seen"] = alert["timestamp"]
                existing["last_seen_epoch"] = now
                return existing
            else:
                new_incident = {
                    "id": incident_id,
                    "title": f"Correlated Attack Incident: {alert['mitre_technique_name']} from {src_ip}",
                    "src_ip": src_ip,
                    "dest_ip": alert["dest_ip"],
                    "mitre_technique_id": tech_id,
                    "mitre_technique_name": alert["mitre_technique_name"],
                    "mitre_tactic_name": alert["mitre_tactic_name"],
                    "severity": "CRITICAL" if count >= 5 else alert["severity"],
                    "event_count": count,
                    "first_seen": alert["timestamp"],
                    "last_seen": alert["timestamp"],
                    "last_seen_epoch": now,
                    "status": "AUTO_ESCALATED"
                }
                self.incidents.insert(0, new_incident)
                if len(self.incidents) > 500:
                    self.incidents.pop()
                logger.info(f"[SIEM CORRELATION] Generated Incident {incident_id} (Count: {count} in 60s)")
                return new_incident
        return None

    def _dispatch_to_soar(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sends an authenticated webhook payload to the SOAR automation service.
        """
        payload = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            self.soar_webhook_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-SOAR-Secret": self.soar_secret
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=0.5) as resp:
                resp_data = resp.read().decode("utf-8")
                return json.loads(resp_data)
        except Exception as e:
            logger.warning(f"Could not deliver webhook to SOAR ({self.soar_webhook_url}): {e}")
            return {"status": "unreachable", "error": str(e)}

    def get_dashboard_summary(self) -> Dict[str, Any]:
        return {
            "total_raw_alerts": len(self.raw_alerts),
            "total_incidents": len(self.incidents),
            "mitre_coverage": dict(self.mitre_stats),
            "recent_alerts": self.raw_alerts[:20],
            "recent_incidents": self.incidents[:10]
        }
