"""
Tests for Enterprise Case Management, Notes, and Audit Trail
"""

import os
import pytest
from soar.models import SOARDatabase


@pytest.fixture
def temp_db(tmp_path):
    db_file = tmp_path / "test_cases.db"
    return SOARDatabase(str(db_file))


def test_case_lifecycle_and_transition(temp_db):
    case_id = temp_db.create_case(
        title="Unauthorized Cloud IAM Role Modification",
        severity="P1_CRITICAL",
        source_ip="198.51.100.23",
        target_asset="arn:aws:iam::role/Admin",
        mitre_technique_id="T1098",
        assignee="analyst-lead@company.com"
    )
    assert case_id is not None

    # Retrieve case
    case = temp_db.get_case(case_id)
    assert case["status"] == "OPEN"
    assert case["severity"] == "P1_CRITICAL"

    # Add Note
    temp_db.add_case_note(case_id, "analyst-lead@company.com", "Confirmed malicious IP. Revoked IAM session.")
    updated_case = temp_db.get_case(case_id)
    assert len(updated_case["notes"]) == 1
    assert "Revoked IAM" in updated_case["notes"][0]["note"]

    # Transition Status to CONTAINED then RESOLVED
    temp_db.update_case_status(case_id, "CONTAINED", actor="analyst-lead@company.com", note="Firewall rule active")
    case = temp_db.get_case(case_id)
    assert case["status"] == "CONTAINED"

    temp_db.update_case_status(case_id, "RESOLVED", actor="analyst-lead@company.com", note="Incident contained and keys rotated")
    case = temp_db.get_case(case_id)
    assert case["status"] == "RESOLVED"
    assert case["resolved_at"] is not None

    # Verify Audit Trail recorded these actions
    audit_logs = temp_db.list_audit_logs()
    assert len(audit_logs) >= 3
