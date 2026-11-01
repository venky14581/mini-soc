"""
Tests for Enterprise Multi-Source Telemetry Ingestion (CloudTrail, Okta, K8s, API)
"""

from siem.ingestion_gateway import EnterpriseIngestionGateway, IngestionPayload, TelemetrySource


def test_aws_root_login_detection():
    gateway = EnterpriseIngestionGateway()
    payload = IngestionPayload(
        source=TelemetrySource.AWS_CLOUDTRAIL,
        event_name="ConsoleLogin",
        src_ip="198.51.100.23",
        user_identity="root",
        target_resource="arn:aws:iam::123456789012:root",
        action_status="SUCCESS",
        raw_event={"mfa_used": "No"}
    )
    result = gateway.ingest_single(payload)
    assert result["detection"] is not None
    assert result["detection"]["matched"] is True
    assert result["detection"]["mitre_technique_id"] == "T1078.004"
    assert result["detection"]["severity"] == "CRITICAL"


def test_okta_mfa_fatigue_detection():
    gateway = EnterpriseIngestionGateway()
    payload = IngestionPayload(
        source=TelemetrySource.OKTA_IDENTITY,
        event_name="user.mfa.verify_push",
        src_ip="185.220.101.5",
        user_identity="victim@company.com",
        action_status="FAILURE",
        raw_event={"consecutive_pushes": 5}
    )
    result = gateway.ingest_single(payload)
    assert result["detection"] is not None
    assert result["detection"]["matched"] is True
    assert result["detection"]["mitre_technique_id"] == "T1621"


def test_saas_api_ssrf_metadata_theft():
    gateway = EnterpriseIngestionGateway()
    payload = IngestionPayload(
        source=TelemetrySource.APP_API,
        event_name="FETCH_URL",
        src_ip="45.154.255.89",
        raw_event={"target_url": "http://169.254.169.254/latest/meta-data/"}
    )
    result = gateway.ingest_single(payload)
    assert result["detection"] is not None
    assert result["detection"]["matched"] is True
    assert result["detection"]["mitre_technique_id"] == "T1552.005"


def test_k8s_container_exec_detection():
    gateway = EnterpriseIngestionGateway()
    payload = IngestionPayload(
        source=TelemetrySource.KUBERNETES_AUDIT,
        event_name="pods/exec",
        src_ip="10.0.0.99",
        user_identity="developer-jane",
        raw_event={"namespace": "production", "container": "api"}
    )
    result = gateway.ingest_single(payload)
    assert result["detection"] is not None
    assert result["detection"]["matched"] is True
    assert result["detection"]["mitre_technique_id"] == "T1609"
