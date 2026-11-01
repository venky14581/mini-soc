"""
Mini-SOC Dynamic Sigma Rule Engine & Evaluator
Parses, tests, and evaluates portable Sigma YAML detection rules in real-time.
"""

import os
import glob
import yaml
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger("siem.sigma_engine")


class SigmaRuleEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        if not rules_dir:
            rules_dir = os.path.join(os.path.dirname(__file__), "..", "sigma-rules")
        self.rules_dir = rules_dir
        self.active_rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self):
        self.active_rules.clear()
        rule_files = glob.glob(os.path.join(self.rules_dir, "*.yml"))
        for rf in rule_files:
            try:
                with open(rf, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    rule["_file_path"] = rf
                    rule["_enabled"] = True
                    self.active_rules.append(rule)
            except Exception as e:
                logger.error(f"Failed to load Sigma rule from {rf}: {e}")
        logger.info(f"Loaded {len(self.active_rules)} dynamic Sigma detection rules")

    def list_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "id": r.get("id"),
                "title": r.get("title"),
                "status": r.get("status"),
                "level": r.get("level"),
                "tags": r.get("tags", []),
                "enabled": r.get("_enabled", True),
                "description": r.get("description", "")
            }
            for r in self.active_rules
        ]

    def test_event_against_rules(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a log event against all active Sigma rules.
        Returns matching rules.
        """
        matches = []
        sig_id = event.get("signature_id") or event.get("alert", {}).get("signature_id")
        event_type = event.get("event_type", "alert")

        for rule in self.active_rules:
            if not rule.get("_enabled", True):
                continue

            detection = rule.get("detection", {})
            selection = detection.get("selection", {})

            # Match signature_id
            rule_sig_ids = selection.get("alert.signature_id")
            if rule_sig_ids:
                if isinstance(rule_sig_ids, list):
                    if sig_id in rule_sig_ids:
                        matches.append(rule)
                elif sig_id == rule_sig_ids:
                    matches.append(rule)

        return matches

    def add_custom_rule(self, rule_yaml_content: str) -> Dict[str, Any]:
        """Allows analysts to deploy a new Sigma rule dynamically."""
        try:
            parsed = yaml.safe_load(rule_yaml_content)
            if "title" not in parsed or "detection" not in parsed:
                raise ValueError("Rule must contain 'title' and 'detection' blocks")
            parsed["_enabled"] = True
            self.active_rules.append(parsed)
            return {"status": "success", "title": parsed["title"], "id": parsed.get("id")}
        except Exception as e:
            return {"status": "error", "message": str(e)}
