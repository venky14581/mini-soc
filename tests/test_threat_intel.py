"""
Tests for Enterprise Threat Intelligence & IoC Engine
"""

from siem.threat_intel import ThreatIntelligenceEngine


def test_known_c2_threat_lookup():
    ti = ThreatIntelligenceEngine()
    result = ti.lookup_ip("198.51.100.23")
    assert result["is_malicious"] is True
    assert result["threat_score"] >= 90
    assert result["category"] == "C2_SERVER"
    assert "APT29" in result["actor"]


def test_tor_exit_node_detection():
    ti = ThreatIntelligenceEngine()
    result = ti.lookup_ip("185.220.101.5")
    assert result["is_malicious"] is True
    assert result["is_tor"] is True
    assert result["category"] == "TOR_EXIT_NODE"


def test_internal_rfc1918_classification():
    ti = ThreatIntelligenceEngine()
    result = ti.lookup_ip("10.0.1.45")
    assert result["is_malicious"] is False
    assert result["threat_score"] == 0
    assert result["category"] == "INTERNAL_NETWORK"


def test_custom_ioc_registration():
    ti = ThreatIntelligenceEngine()
    ti.register_custom_ioc("203.0.113.88", 99, "RANSOMWARE_OPERATOR", "LOCKBIT_VARIANT", "Active affiliate listener")
    res = ti.lookup_ip("203.0.113.88")
    assert res["is_malicious"] is True
    assert res["threat_score"] == 99
    assert res["actor"] == "LOCKBIT_VARIANT"
