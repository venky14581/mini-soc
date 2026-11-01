"""
Tests for SOC 2 Type II, ISO 27001, and PCI-DSS Compliance Reporting
"""

from siem.compliance_report import ComplianceReportingEngine


def test_soc2_compliance_assessment_generation():
    engine = ComplianceReportingEngine()
    report = engine.generate_soc2_report()

    assert report["overall_status"] == "AUDIT_READY"
    assert "SOC_2_TYPE_II" in report["frameworks"]
    assert "ISO_27001_2022" in report["frameworks"]
    assert "PCI_DSS_V4" in report["frameworks"]

    soc2_controls = report["frameworks"]["SOC_2_TYPE_II"]["controls"]
    assert len(soc2_controls) >= 4
    control_ids = [c["control_id"] for c in soc2_controls]
    assert any("CC6.1" in cid for cid in control_ids)
    assert any("CC7.2" in cid for cid in control_ids)
    assert any("CC7.3" in cid for cid in control_ids)

    # Check metrics present
    assert "mtta" in report["metrics"]
    assert "mttr" in report["metrics"]
    assert "sla_compliance_rate" in report["metrics"]
