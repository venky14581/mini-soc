"""
Tests for Enterprise SOAR Integrations (Slack, Jira, Cloud WAF, Okta)
"""

from soar.integrations import EnterpriseIntegrationsDispatcher


def test_slack_interactive_notification():
    dispatcher = EnterpriseIntegrationsDispatcher()
    res = dispatcher.notify_slack_interactive(
        case_id="CASE-2026-0005",
        title="Unauthorized Cloud IAM Access",
        severity="P1_CRITICAL",
        src_ip="198.51.100.23",
        mitre_tech="T1078.004",
        playbook="aws_iam_contain"
    )
    assert res["status"] == "dispatched"
    assert res["service"] == "SLACK"
    assert "blocks" in res["payload"]


def test_jira_security_ticket_creation():
    dispatcher = EnterpriseIntegrationsDispatcher()
    res = dispatcher.create_jira_security_ticket(
        case_id="CASE-2026-0005",
        title="Unauthorized Cloud IAM Access",
        severity="P1_CRITICAL",
        details="Automated session revoked and IP blocked on WAF",
        mitre_tech="T1078.004"
    )
    assert res["status"] == "created"
    assert res["service"] == "JIRA"
    assert "ticket_key" in res
    assert res["ticket"]["priority"] == "Highest"


def test_cloud_waf_and_identity_revocation():
    dispatcher = EnterpriseIntegrationsDispatcher()
    waf_res = dispatcher.block_cloud_waf_ip("198.51.100.23", "Malicious C2 node")
    assert waf_res["status"] == "ENFORCED"
    assert waf_res["target_ip"] == "198.51.100.23"

    id_res = dispatcher.revoke_identity_session("compromised-admin@company.com", "MFA fatigue compromise")
    assert id_res["status"] == "REVOKED"
    assert id_res["target_user"] == "compromised-admin@company.com"
