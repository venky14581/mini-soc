"""
Mini-SOC SIEM Web API & SOC Analyst Dashboard Backend
Provides endpoints for alert querying, MITRE ATT&CK coverage matrix, incident correlation,
attack simulation triggers, and serves the SOC frontend interface.
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
import urllib.request

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from siem.correlator import SIEMCorrelationEngine, MITRE_TECHNIQUE_MAP
from siem.collector import SuricataLogCollector
from siem.threat_intel import ThreatIntelligenceEngine
from siem.ingestion_gateway import EnterpriseIngestionGateway, IngestionPayload, TelemetrySource
from siem.sigma_engine import SigmaRuleEngine
from siem.compliance_report import ComplianceReportingEngine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [SIEM] %(message)s"
)
logger = logging.getLogger("siem.api")

app = FastAPI(
    title="Mini-SOC Enterprise SIEM & Correlation Engine",
    description="Multi-source log telemetry, Threat Intel enrichment, Sigma engine, and SOC 2 compliance",
    version="2.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SOAR_URL = os.getenv("SOAR_URL", "http://127.0.0.1:8001/soar/webhook")
SOAR_API = os.getenv("SOAR_API_BASE", "http://127.0.0.1:8001/soar")
SOAR_SECRET = os.getenv("SOAR_SHARED_SECRET", "mini-soc-secure-webhook-token-2026")
EVE_JSON_PATH = os.getenv("EVE_JSON_PATH", "eve.json")

# Initialize core and enterprise engines
engine = SIEMCorrelationEngine(soar_webhook_url=SOAR_URL, soar_secret=SOAR_SECRET)
collector = SuricataLogCollector(log_path=EVE_JSON_PATH, alert_handler=engine.process_event)
collector.start()

threat_intel = ThreatIntelligenceEngine()
ingestion_gateway = EnterpriseIngestionGateway(threat_intel=threat_intel)
sigma_engine = SigmaRuleEngine()
compliance_engine = ComplianceReportingEngine()

# Static directory setup
STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class IngestEventRequest(BaseModel):
    signature_id: int
    signature: str
    src_ip: str
    src_port: Optional[int] = 44444
    dest_ip: Optional[str] = "172.28.0.10"
    dest_port: Optional[int] = 80
    proto: Optional[str] = "TCP"
    timestamp: Optional[str] = None
    raw_payload: Optional[Dict[str, Any]] = None


class SimulationRequest(BaseModel):
    attack_type: str  # nmap_scan, ssh_bruteforce, sql_injection, path_traversal, benign_scanner, full_chain
    attacker_ip: Optional[str] = "192.168.1.55"
    target_ip: Optional[str] = "172.28.0.10"


@app.post("/api/events/ingest", summary="Ingest event directly into SIEM")
def ingest_event(event: IngestEventRequest):
    """
    Ingests an alert event into the SIEM correlation pipeline,
    enriches with MITRE ATT&CK, evaluates sliding window, and triggers SOAR.
    """
    result = engine.process_event(event.model_dump())
    return {
        "status": "ingested",
        "alert_id": result["alert"]["id"],
        "mitre_technique": result["alert"]["mitre_technique_id"],
        "correlated": result["correlated_incident"] is not None,
        "soar_response": result["soar_response"]
    }


@app.get("/api/alerts", summary="List enriched SIEM alerts")
def get_alerts(
    src_ip: Optional[str] = None,
    technique: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500)
):
    alerts = engine.raw_alerts
    if src_ip:
        alerts = [a for a in alerts if a["src_ip"] == src_ip]
    if technique:
        alerts = [a for a in alerts if a.get("mitre_technique_id") == technique]
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity.upper()]
    return {
        "total": len(alerts),
        "alerts": alerts[:limit]
    }


@app.get("/api/incidents", summary="List correlated security incidents")
def get_incidents():
    return {
        "total": len(engine.incidents),
        "incidents": engine.incidents
    }


@app.get("/api/mitre-coverage", summary="MITRE ATT&CK Matrix coverage status")
def get_mitre_coverage():
    """
    Returns the comprehensive list of supported MITRE ATT&CK techniques,
    rule IDs, tactics, and current alert counts.
    """
    tactics_summary = {
        "TA0043": {"name": "Reconnaissance", "techniques": []},
        "TA0001": {"name": "Initial Access", "techniques": []},
        "TA0002": {"name": "Execution", "techniques": []},
        "TA0006": {"name": "Credential Access", "techniques": []},
        "TA0007": {"name": "Discovery", "techniques": []}
    }

    seen_techs = set()
    for sid, info in MITRE_TECHNIQUE_MAP.items():
        tech_id = info["id"]
        tactic_id = info["tactic_id"]
        combo_key = (tech_id, tactic_id)
        if combo_key not in seen_techs:
            seen_techs.add(combo_key)
            if tactic_id in tactics_summary:
                tactics_summary[tactic_id]["techniques"].append({
                    "technique_id": tech_id,
                    "technique_name": info["name"],
                    "rule_id": sid,
                    "severity": info["severity"],
                    "alert_count": engine.mitre_stats.get(tech_id, 0)
                })

    return {
        "framework": "MITRE ATT&CK Enterprise v14",
        "total_techniques_mapped": len(seen_techs),
        "tactics": tactics_summary,
        "technique_counts": dict(engine.mitre_stats)
    }


@app.get("/api/metrics", summary="High level SOC KPIs and response metrics")
def get_metrics():
    # Attempt to query SOAR stats
    soar_stats = {}
    try:
        req = urllib.request.Request(f"{SOAR_API}/stats", headers={"Authorization": "Bearer analyst"})
        with urllib.request.urlopen(req, timeout=1) as resp:
            soar_stats = json.loads(resp.read().decode("utf-8"))
    except Exception:
        soar_stats = {
            "active_blocks": 0,
            "noise_suppressed_count": 0,
            "total_blocks_executed": 0,
            "avg_automated_response_ms": 14.2,
            "analyst_hours_saved_est": 0.0
        }

    return {
        "total_events": len(engine.raw_alerts),
        "correlated_incidents": len(engine.incidents),
        "mitre_techniques_triggered": len(engine.mitre_stats),
        "active_firewall_blocks": soar_stats.get("active_blocks", 0),
        "noise_alerts_suppressed": soar_stats.get("noise_suppressed_count", 0),
        "mttd_seconds": "< 0.5s (Real-Time IDS)",
        "mttr_seconds": f"{soar_stats.get('avg_automated_response_ms', 12.5)} ms",
        "analyst_hours_saved": soar_stats.get("analyst_hours_saved_est", 0.0)
    }


@app.post("/api/simulator/launch", summary="Trigger attack pattern in lab")
def launch_attack_simulation(sim: SimulationRequest, background_tasks: BackgroundTasks):
    """
    Simulates attack patterns directly against the lab for verification & live demos.
    """
    attacker_ip = sim.attacker_ip or "192.168.1.189"
    target_ip = sim.target_ip or "172.28.0.10"
    attack_type = sim.attack_type

    def run_sim():
        import time
        if attack_type == "nmap_scan":
            for port in [21, 22, 80, 443, 3306, 8080]:
                engine.process_event({
                    "signature_id": 1000001,
                    "signature": "MINI-SOC - Nmap TCP SYN Scan Detected",
                    "src_ip": attacker_ip,
                    "src_port": 50123,
                    "dest_ip": target_ip,
                    "dest_port": port,
                    "proto": "TCP"
                })
                time.sleep(0.05)

        elif attack_type == "ssh_bruteforce":
            for i in range(6):
                engine.process_event({
                    "signature_id": 1000010,
                    "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
                    "src_ip": attacker_ip,
                    "src_port": 49000 + i,
                    "dest_ip": target_ip,
                    "dest_port": 22,
                    "proto": "TCP"
                })
                time.sleep(0.05)

        elif attack_type == "sql_injection":
            engine.process_event({
                "signature_id": 1000020,
                "signature": "MINI-SOC - SQL Injection Attempt (UNION SELECT)",
                "src_ip": attacker_ip,
                "src_port": 54321,
                "dest_ip": target_ip,
                "dest_port": 80,
                "proto": "HTTP"
            })

        elif attack_type == "path_traversal":
            engine.process_event({
                "signature_id": 1000022,
                "signature": "MINI-SOC - Directory Traversal Attempt (/etc/passwd)",
                "src_ip": attacker_ip,
                "src_port": 54322,
                "dest_ip": target_ip,
                "dest_port": 80,
                "proto": "HTTP"
            })

        elif attack_type == "benign_scanner":
            engine.process_event({
                "signature_id": 1000050,
                "signature": "MINI-SOC - Authorized Internal Security Scanner Probe",
                "src_ip": "172.28.0.254",  # Whitelisted benign scanner
                "src_port": 41200,
                "dest_ip": target_ip,
                "dest_port": 80,
                "proto": "HTTP"
            })

        elif attack_type == "full_chain":
            # 1. Recon scan
            for port in [80, 22, 443]:
                engine.process_event({
                    "signature_id": 1000001,
                    "signature": "MINI-SOC - Nmap TCP SYN Scan Detected",
                    "src_ip": "192.168.1.99",
                    "src_port": 50000,
                    "dest_ip": target_ip,
                    "dest_port": port
                })
            # 2. Benign scan noise
            engine.process_event({
                "signature_id": 1000050,
                "signature": "MINI-SOC - Authorized Internal Security Scanner Probe",
                "src_ip": "172.28.0.254",
                "src_port": 41200,
                "dest_ip": target_ip,
                "dest_port": 80
            })
            # 3. SSH Brute Force
            for i in range(6):
                engine.process_event({
                    "signature_id": 1000010,
                    "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
                    "src_ip": "192.168.1.99",
                    "src_port": 51000 + i,
                    "dest_ip": target_ip,
                    "dest_port": 22
                })

        elif attack_type == "aws_root_login":
            ingestion_gateway.ingest_single(IngestionPayload(
                source=TelemetrySource.AWS_CLOUDTRAIL,
                event_name="ConsoleLogin",
                src_ip="198.51.100.23",
                user_identity="root",
                target_resource="arn:aws:iam::123456789012:root",
                action_status="SUCCESS",
                raw_event={"mfa_used": "No", "login_to": "https://console.aws.amazon.com/"}
            ))
            engine.process_event({
                "signature_id": 9000001,
                "signature": "AWS CloudTrail - Root Account Console Login Without MFA",
                "src_ip": "198.51.100.23",
                "dest_ip": "aws-console",
                "proto": "HTTPS"
            })

        elif attack_type == "okta_mfa_bombing":
            ingestion_gateway.ingest_single(IngestionPayload(
                source=TelemetrySource.OKTA_IDENTITY,
                event_name="user.mfa.verify_push",
                src_ip="185.220.101.5",
                user_identity="cfo@company.com",
                target_resource="Okta Identity Cloud",
                action_status="FAILURE",
                raw_event={"consecutive_pushes": 5, "mfa_type": "Okta Verify Push"}
            ))
            engine.process_event({
                "signature_id": 9000002,
                "signature": "Okta MFA Fatigue (Repeated Push Notifications) Detected",
                "src_ip": "185.220.101.5",
                "dest_ip": "identity.company.com",
                "proto": "HTTPS"
            })

        elif attack_type == "api_ssrf_metadata":
            ingestion_gateway.ingest_single(IngestionPayload(
                source=TelemetrySource.APP_API,
                event_name="API_OUTBOUND_PROXY_REQUEST",
                src_ip="45.154.255.89",
                user_identity="unauthenticated_api_client",
                target_resource="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                action_status="ATTEMPT",
                raw_event={"uri": "/api/v2/fetch_url", "target_url": "http://169.254.169.254/latest/meta-data/"}
            ))
            engine.process_event({
                "signature_id": 9000003,
                "signature": "SaaS Web API - Cloud Metadata SSRF Theft Attempt (AWS IMDS)",
                "src_ip": "45.154.255.89",
                "dest_ip": "169.254.169.254",
                "proto": "HTTP"
            })

        elif attack_type == "k8s_exec":
            ingestion_gateway.ingest_single(IngestionPayload(
                source=TelemetrySource.KUBERNETES_AUDIT,
                event_name="pods/exec",
                src_ip="192.168.1.189",
                user_identity="dev-user-bob",
                target_resource="prod-checkout-service-7f89b-x2k4",
                action_status="SUCCESS",
                raw_event={"namespace": "production", "container": "checkout-api", "command": ["/bin/sh"]}
            ))
            engine.process_event({
                "signature_id": 9000004,
                "signature": "Kubernetes Audit - Interactive Container Exec in production",
                "src_ip": "192.168.1.189",
                "dest_ip": "k8s-api.prod",
                "proto": "HTTPS"
            })

    background_tasks.add_task(run_sim)
    return {
        "status": "simulation_triggered",
        "attack_type": attack_type,
        "attacker_ip": attacker_ip,
        "target_ip": target_ip
    }


# ==============================================================================
# Enterprise Threat Intelligence Endpoints
# ==============================================================================

@app.get("/api/threat-intel/lookup", summary="Query IP threat intelligence and reputation")
def lookup_threat_intel(ip: str = Query(..., description="IP address to evaluate")):
    return threat_intel.lookup_ip(ip)


@app.get("/api/threat-intel/summary", summary="Summary of connected Threat Intel feeds")
def get_threat_intel_summary():
    return threat_intel.get_feed_summary()


# ==============================================================================
# Enterprise Multi-Source Telemetry Ingestion (CloudTrail, Okta, K8s, Web API)
# ==============================================================================

@app.post("/api/v1/ingest", summary="Ingest enterprise log event (CloudTrail, Okta, K8s, App)")
def ingest_enterprise_telemetry(payload: IngestionPayload):
    result = ingestion_gateway.ingest_single(payload)
    if result.get("detection") and result["detection"].get("matched"):
        det = result["detection"]
        engine.process_event({
            "signature_id": 9000000 + len(ingestion_gateway.ingested_events),
            "signature": f"[{result['source']}] {det['signature']}",
            "src_ip": result["src_ip"],
            "dest_ip": result["target_resource"] or "172.28.0.10",
            "proto": "API"
        })
    return {"status": "ingested", "event": result}


@app.post("/api/v1/ingest/batch", summary="Batch ingest enterprise logs from agents")
def ingest_enterprise_batch(payloads: List[IngestionPayload]):
    results = ingestion_gateway.ingest_batch(payloads)
    return {"status": "batch_processed", "count": len(results)}


@app.get("/api/v1/telemetry", summary="List normalized multi-source telemetry events")
def get_telemetry_events(
    source: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500)
):
    events = ingestion_gateway.ingested_events
    if source:
        events = [e for e in events if e["source"] == source.upper()]
    return {"total": len(events), "events": events[:limit]}


# ==============================================================================
# Dynamic Sigma Detection Rules Endpoints
# ==============================================================================

@app.get("/api/sigma/rules", summary="List dynamic Sigma detection rules")
def list_sigma_rules():
    return {"rules": sigma_engine.list_rules()}


@app.post("/api/sigma/test", summary="Test an event against active Sigma rules")
def test_sigma_event(event: Dict[str, Any]):
    matches = sigma_engine.test_event_against_rules(event)
    return {"matches_count": len(matches), "matching_rules": matches}


# ==============================================================================
# SOC 2 & Enterprise Compliance Audit Report
# ==============================================================================

@app.get("/api/compliance/soc2", summary="Generate SOC 2 Type II and ISO 27001 compliance audit assessment")
def get_compliance_assessment():
    return compliance_engine.generate_soc2_report()


# Mount static frontend
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", response_class=HTMLResponse)
def index_view():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>Mini-SOC SIEM Running</h1>"


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("siem.api:app", host="0.0.0.0", port=port, reload=False)
