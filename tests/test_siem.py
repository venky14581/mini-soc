"""
Unit tests for SIEM Correlation Engine
Validates MITRE ATT&CK mapping, alert enrichment, and sliding-window event aggregation.
"""

from siem.correlator import SIEMCorrelationEngine, MITRE_TECHNIQUE_MAP


def test_mitre_enrichment():
    engine = SIEMCorrelationEngine()

    raw_event = {
        "signature_id": 1000001,
        "signature": "MINI-SOC - Nmap TCP SYN Scan Detected",
        "src_ip": "10.0.0.99",
        "dest_ip": "172.28.0.10",
        "proto": "TCP"
    }

    enriched = engine.enrich_alert(raw_event)
    assert enriched["mitre_technique_id"] == "T1046"
    assert enriched["mitre_technique_name"] == "Network Service Scanning"
    assert enriched["mitre_tactic_name"] == "Discovery"
    assert enriched["severity"] == "HIGH"


def test_sliding_window_correlation():
    engine = SIEMCorrelationEngine()
    attacker = "192.168.10.15"

    # Send 4 SSH alerts -> should not trigger incident yet (threshold = 5)
    incident = None
    for i in range(4):
        res = engine.process_event({
            "signature_id": 1000010,
            "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
            "src_ip": attacker,
            "dest_ip": "172.28.0.10",
            "proto": "TCP"
        })
        incident = res["correlated_incident"]

    assert incident is None
    assert len(engine.incidents) == 0

    # 5th alert within window triggers correlated incident!
    res = engine.process_event({
        "signature_id": 1000010,
        "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
        "src_ip": attacker,
        "dest_ip": "172.28.0.10",
        "proto": "TCP"
    })
    incident = res["correlated_incident"]
    assert incident is not None
    assert incident["src_ip"] == attacker
    assert incident["mitre_technique_id"] == "T1110.001"
    assert incident["event_count"] >= 5
    assert len(engine.incidents) == 1
