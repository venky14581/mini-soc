"""
Tests for Mini-SOC Suricata & Sigma Detection Rules
Validates rule syntax, SID uniqueness, and MITRE ATT&CK mapping tags.
"""

import os
import re
import glob
import yaml
import pytest


RULES_DIR = os.path.join(os.path.dirname(__file__), "..", "suricata", "rules")
SIGMA_DIR = os.path.join(os.path.dirname(__file__), "..", "sigma-rules")


def test_suricata_rules_syntax_and_mitre_mapping():
    rule_files = glob.glob(os.path.join(RULES_DIR, "*.rules"))
    assert len(rule_files) > 0, "No Suricata rule files found!"

    sid_seen = set()
    total_rules = 0

    for r_file in rule_files:
        with open(r_file, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                total_rules += 1
                assert line.startswith("alert "), f"Rule at line {line_no} does not start with 'alert': {line}"

                # Check SID
                sid_match = re.search(r'sid\s*:\s*(\d+)\s*;', line)
                assert sid_match, f"Rule missing SID at line {line_no}: {line}"
                sid = int(sid_match.group(1))
                assert sid not in sid_seen, f"Duplicate SID {sid} found in {r_file} at line {line_no}"
                sid_seen.add(sid)

                # Check MITRE ATT&CK mapping metadata
                assert "mitre_technique_id" in line, f"Rule {sid} missing MITRE technique metadata in {r_file}"
                assert "classtype" in line, f"Rule {sid} missing classtype in {r_file}"

    assert total_rules >= 10, f"Expected at least 10 custom detection rules, found {total_rules}"


def test_sigma_rules_validity():
    sigma_files = glob.glob(os.path.join(SIGMA_DIR, "*.yml"))
    assert len(sigma_files) >= 5, f"Expected at least 5 Sigma rules, found {len(sigma_files)}"

    for s_file in sigma_files:
        with open(s_file, "r", encoding="utf-8") as f:
            rule_data = yaml.safe_load(f)

        assert "title" in rule_data, f"Sigma rule {s_file} missing title"
        assert "logsource" in rule_data, f"Sigma rule {s_file} missing logsource"
        assert "detection" in rule_data, f"Sigma rule {s_file} missing detection block"
        assert "condition" in rule_data["detection"], f"Sigma rule {s_file} missing detection condition"
        assert "tags" in rule_data, f"Sigma rule {s_file} missing tags"

        # Check MITRE tag presence
        has_mitre_tag = any(tag.startswith("attack.t") or tag.startswith("attack.") for tag in rule_data["tags"])
        assert has_mitre_tag, f"Sigma rule {s_file} has no MITRE ATT&CK tag"
