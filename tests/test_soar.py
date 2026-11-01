"""
Unit tests for SOAR Automation Service
Tests webhook authentication, playbook trigger logic, IP containment,
noise suppression, and action reversibility.
"""

import pytest
from fastapi.testclient import TestClient
from soar.automation import app, db, SOAR_SHARED_SECRET
from soar.models import AlertPayload

client = TestClient(app)


def test_soar_webhook_authentication():
    payload = {
        "src_ip": "192.168.1.50",
        "signature": "Test Scan",
        "signature_id": 1000001,
        "mitre_technique_id": "T1046"
    }

    # Request without secret header should fail (401)
    res_no_auth = client.post("/soar/webhook", json=payload)
    assert res_no_auth.status_code == 401

    # Request with invalid secret should fail (401)
    res_bad_auth = client.post(
        "/soar/webhook",
        json=payload,
        headers={"X-SOAR-Secret": "invalid-secret-key"}
    )
    assert res_bad_auth.status_code == 401

    # Request with valid secret should succeed (200)
    res_valid = client.post(
        "/soar/webhook",
        json=payload,
        headers={"X-SOAR-Secret": SOAR_SHARED_SECRET}
    )
    assert res_valid.status_code == 200
    data = res_valid.json()
    assert data["status"] == "processed"


def test_ssh_brute_force_playbook_block():
    target_attacker = "192.168.1.77"
    # Ensure unblocked initially
    db.remove_active_block(target_attacker)

    payload = {
        "src_ip": target_attacker,
        "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
        "signature_id": 1000010,
        "mitre_technique_id": "T1110.001"
    }

    res = client.post(
        "/soar/webhook",
        json=payload,
        headers={"X-SOAR-Secret": SOAR_SHARED_SECRET}
    )
    assert res.status_code == 200
    result = res.json()["result"]
    assert result["playbook"] == "ssh_bruteforce_block"
    assert result["action_taken"] == "BLOCK_IP"
    assert result["target"] == target_attacker

    # Verify IP is registered in active blocks
    assert db.is_target_blocked(target_attacker) is True


def test_benign_scanner_noise_suppression_playbook():
    benign_ip = "172.28.0.254"
    payload = {
        "src_ip": benign_ip,
        "signature": "MINI-SOC - Authorized Internal Security Scanner Probe",
        "signature_id": 1000050,
        "mitre_technique_id": "T1595"
    }

    res = client.post(
        "/soar/webhook",
        json=payload,
        headers={"X-SOAR-Secret": SOAR_SHARED_SECRET}
    )
    assert res.status_code == 200
    result = res.json()["result"]
    assert result["playbook"] == "benign_scanner_suppress"
    assert result["action_taken"] == "AUTO_TAG_NOISE"
    assert result["status"] == "SUPPRESSED_BENIGN"

    # Benign scanner must NEVER be blocked on firewall
    assert db.is_target_blocked(benign_ip) is False


def test_action_reversibility():
    test_ip = "192.168.1.88"
    # Trigger a block first
    payload = {
        "src_ip": test_ip,
        "signature": "MINI-SOC - SQL Injection Attempt (UNION SELECT)",
        "signature_id": 1000020,
        "mitre_technique_id": "T1190"
    }
    res = client.post(
        "/soar/webhook",
        json=payload,
        headers={"X-SOAR-Secret": SOAR_SHARED_SECRET}
    )
    action_id = res.json()["result"]["action_id"]
    assert db.is_target_blocked(test_ip) is True

    # Revert the action
    revert_res = client.post(
        f"/soar/actions/{action_id}/revert",
        headers={"Authorization": "Bearer analyst"}
    )
    assert revert_res.status_code == 200
    assert revert_res.json()["status"] == "success"

    # Verify the target is no longer in active_blocks
    assert db.is_target_blocked(test_ip) is False
    action = db.get_action_by_id(action_id)
    assert action["status"] == "REVERTED"
