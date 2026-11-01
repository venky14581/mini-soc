"""
Mini-SOC Enterprise Multi-Source Log Ingestion Gateway
Normalizes, enriches, and evaluates telemetry from CloudTrail, Okta,
Kubernetes Audit, SaaS Web APIs, and Network IDS.
"""

import time
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from siem.threat_intel import ThreatIntelligenceEngine

logger = logging.getLogger("siem.ingestion_gateway")


class TelemetrySource:
    SURICATA_NIDS = "SURICATA_NIDS"
    AWS_CLOUDTRAIL = "AWS_CLOUDTRAIL"
    OKTA_IDENTITY = "OKTA_IDENTITY"
    APP_API = "APP_API"
    KUBERNETES_AUDIT = "KUBERNETES_AUDIT"
    HOST_SYSLOG = "HOST_SYSLOG"


class IngestionPayload(BaseModel):
    source: str = Field(..., description="Telemetry source identifier (AWS_CLOUDTRAIL, OKTA_IDENTITY, APP_API, etc.)")
    event_name: str
    src_ip: Optional[str] = "0.0.0.0"
    user_identity: Optional[str] = None
    target_resource: Optional[str] = None
    action_status: str = "SUCCESS"  # SUCCESS, FAILURE, ATTEMPT
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[str] = None


class EnterpriseIngestionGateway:
    def __init__(self, threat_intel: Optional[ThreatIntelligenceEngine] = None):
        self.threat_intel = threat_intel or ThreatIntelligenceEngine()
        self.ingested_events: List[Dict[str, Any]] = []

    def ingest_single(self, payload: IngestionPayload) -> Dict[str, Any]:
        now_iso = datetime.now(timezone.utc).isoformat()
        src_ip = payload.src_ip or "0.0.0.0"

        # 1. Threat Intelligence Enrichment
        ti_info = self.threat_intel.lookup_ip(src_ip)

        # 2. Universal Telemetry Schema Normalization
        event_id = f"EVT-{int(time.time() * 1000)}-{len(self.ingested_events) + 1}"
        normalized = {
            "id": event_id,
            "timestamp": payload.timestamp or now_iso,
            "source": payload.source.upper(),
            "event_name": payload.event_name,
            "src_ip": src_ip,
            "user_identity": payload.user_identity,
            "target_resource": payload.target_resource,
            "action_status": payload.action_status,
            "threat_intel": ti_info,
            "raw_event": payload.raw_event
        }

        # 3. Cloud / Identity / App Threat Rule Evaluation
        detection = self._evaluate_enterprise_signatures(normalized)
        normalized["detection"] = detection

        self.ingested_events.insert(0, normalized)
        if len(self.ingested_events) > 5000:
            self.ingested_events.pop()

        return normalized

    def ingest_batch(self, payloads: List[IngestionPayload]) -> List[Dict[str, Any]]:
        results = []
        for p in payloads:
            results.append(self.ingest_single(p))
        return results

    def _evaluate_enterprise_signatures(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        source = event["source"]
        event_name = event["event_name"].lower()
        src_ip = event["src_ip"]
        raw = event["raw_event"]
        ti = event["threat_intel"]

        # Rule 1: AWS CloudTrail - Root Account Console Login (MITRE T1078.004)
        if source == TelemetrySource.AWS_CLOUDTRAIL and ("consolelogin" in event_name or "root" in str(event.get("user_identity", "")).lower()):
            if event["action_status"] == "SUCCESS" and "root" in str(event.get("user_identity", "")).lower():
                return {
                    "matched": True,
                    "signature": "AWS CloudTrail - Root Account Console Login Detected",
                    "severity": "CRITICAL",
                    "mitre_technique_id": "T1078.004",
                    "mitre_technique_name": "Valid Accounts: Cloud Accounts",
                    "tactic": "Initial Access",
                    "reason": "Root account login should strictly be avoided in production environments"
                }

        # Rule 2: AWS CloudTrail - Public S3 Bucket Policy Exposure (MITRE T1530)
        if source == TelemetrySource.AWS_CLOUDTRAIL and "putbucketpolicy" in event_name:
            if "Principal': '*'" in str(raw) or 'Principal": "*"' in str(raw) or raw.get("is_public", False):
                return {
                    "matched": True,
                    "signature": "AWS S3 Bucket Policy Exposing Data Publicly",
                    "severity": "CRITICAL",
                    "mitre_technique_id": "T1530",
                    "mitre_technique_name": "Data from Cloud Storage",
                    "tactic": "Exfiltration",
                    "reason": "Bucket policy contains wildcard principal allowing public access"
                }

        # Rule 3: Okta / Auth0 - MFA Fatigue Attack / Push Bombing (MITRE T1621)
        if source == TelemetrySource.OKTA_IDENTITY and ("mfa_push" in event_name or "verify_push" in event_name):
            if event["action_status"] == "FAILURE" or raw.get("consecutive_pushes", 0) >= 3:
                return {
                    "matched": True,
                    "signature": "Okta MFA Fatigue (Repeated Push Notifications) Detected",
                    "severity": "HIGH",
                    "mitre_technique_id": "T1621",
                    "mitre_technique_name": "Multi-Factor Authentication Request Generation",
                    "tactic": "Credential Access",
                    "reason": "Repeated unauthorized MFA push challenges sent to corporate identity"
                }

        # Rule 4: SaaS API - Cloud Metadata Service SSRF Probe (MITRE T1552.005)
        if source == TelemetrySource.APP_API:
            uri_or_param = str(raw.get("uri", "")) + str(raw.get("query", "")) + str(raw.get("target_url", ""))
            if "169.254.169.254" in uri_or_param or "latest/meta-data" in uri_or_param:
                return {
                    "matched": True,
                    "signature": "SaaS Web API - Cloud Metadata SSRF Theft Attempt (AWS IMDS)",
                    "severity": "CRITICAL",
                    "mitre_technique_id": "T1552.005",
                    "mitre_technique_name": "Cloud Instance Metadata API",
                    "tactic": "Credential Access",
                    "reason": "Client attempted to extract IAM role credentials via Instance Metadata Service"
                }

        # Rule 5: Kubernetes Audit - Unauthorized Exec into Production Pod (MITRE T1609)
        if source == TelemetrySource.KUBERNETES_AUDIT and "pods/exec" in event_name:
            namespace = raw.get("namespace", "default")
            if namespace in ("prod", "production", "payments"):
                return {
                    "matched": True,
                    "signature": f"Kubernetes Audit - Interactive Container Exec in {namespace}",
                    "severity": "HIGH",
                    "mitre_technique_id": "T1609",
                    "mitre_technique_name": "Container Administration Command",
                    "tactic": "Execution",
                    "reason": "Direct shell/command execution invoked inside isolated production pod"
                }

        # Rule 6: Threat Intel Match on Any Telemetry Source (MITRE T1071)
        if ti.get("is_malicious"):
            return {
                "matched": True,
                "signature": f"Threat Intel Match: Traffic from Known Malicious {ti['category']}",
                "severity": "CRITICAL" if ti["threat_score"] >= 80 else "HIGH",
                "mitre_technique_id": "T1071",
                "mitre_technique_name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "reason": f"IP {src_ip} matches active threat feed: {ti['description']} (Actor: {ti['actor']})"
            }

        return None
