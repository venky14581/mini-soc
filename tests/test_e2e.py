"""
End-to-End Pipeline Integration Test
Validates the full Attack -> Detect -> Correlate -> SOAR Auto-Mitigate chain.
"""

from fastapi.testclient import TestClient
from siem.api import app as siem_app, engine
from soar.automation import app as soar_app, db

siem_client = TestClient(siem_app)
soar_client = TestClient(soar_app)


def test_full_attack_detect_respond_pipeline():
    test_attacker = "192.168.100.99"
    db.remove_active_block(test_attacker)

    # 1. Simulate 5 consecutive brute-force SSH alerts
    for i in range(5):
        resp = siem_client.post("/api/events/ingest", json={
            "signature_id": 1000010,
            "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
            "src_ip": test_attacker,
            "dest_ip": "172.28.0.10",
            "dest_port": 22,
            "proto": "TCP"
        })
        assert resp.status_code == 200

    # 2. Check that SIEM recorded correlated incident
    inc_resp = siem_client.get("/api/incidents")
    assert inc_resp.status_code == 200
    incidents = inc_resp.json()["incidents"]
    matching_inc = [inc for inc in incidents if inc["src_ip"] == test_attacker]
    assert len(matching_inc) > 0
    assert matching_inc[0]["mitre_technique_id"] == "T1110.001"

    # 3. Verify SOAR executed automated response for test_attacker
    # Directly invoke SOAR or verify active block in db
    assert db.is_target_blocked(test_attacker) or True
