"""
Mini-SOC Enterprise Threat Intelligence & IoC Enrichment Engine
Enriches log telemetry with IP reputation, Tor exit node detection,
known adversary infrastructure, GeoIP resolution, and threat scoring.
"""

import ipaddress
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone

logger = logging.getLogger("siem.threat_intel")

# Known Malicious Indicator Registry (Simulates feeds from AlienVault OTX, AbuseIPDB, and Tor Project)
KNOWN_BAD_ACTORS = {
    "198.51.100.23": {
        "score": 95,
        "category": "C2_SERVER",
        "actor": "APT29_COZYBEAR_INFRA",
        "description": "Known Command and Control listener associated with supply-chain campaigns",
        "country": "RU",
        "city": "Moscow",
        "asn": "AS48282"
    },
    "185.220.101.5": {
        "score": 85,
        "category": "TOR_EXIT_NODE",
        "actor": "TOR_ANONYMIZER",
        "description": "Active Tor Exit Node frequently utilized for credential stuffing",
        "country": "DE",
        "city": "Frankfurt",
        "asn": "AS206238"
    },
    "45.154.255.89": {
        "score": 90,
        "category": "BOTNET_SCANNER",
        "actor": "MIRAI_VARIANT",
        "description": "Automated brute-force scanning botnet targeting SSH and Web APIs",
        "country": "NL",
        "city": "Amsterdam",
        "asn": "AS49981"
    },
    "192.168.1.189": {
        "score": 88,
        "category": "LAB_ATTACKER_IOC",
        "actor": "OFFENSIVE_SIMULATOR",
        "description": "High-velocity offensive testing workstation (simulated adversary)",
        "country": "US",
        "city": "San Francisco",
        "asn": "AS13335"
    }
}

# Subnets known to host bulletproof hosting or anonymous proxy providers
SUSPICIOUS_CIDRS = [
    ipaddress.ip_network("185.220.100.0/22"), # Tor exit nodes
    ipaddress.ip_network("194.26.29.0/24"),   # Bulletproof hosting
]


class ThreatIntelligenceEngine:
    def __init__(self):
        self.ioc_cache: Dict[str, Dict[str, Any]] = dict(KNOWN_BAD_ACTORS)
        self.lookup_history: List[Dict[str, Any]] = []

    def lookup_ip(self, ip_str: str) -> Dict[str, Any]:
        """
        Queries the Threat Intel engine for IP reputation and enrichment metadata.
        """
        # 1. Exact match in IoC registry
        if ip_str in self.ioc_cache:
            entry = self.ioc_cache[ip_str]
            result = {
                "ip": ip_str,
                "is_malicious": True,
                "threat_score": entry["score"],
                "category": entry["category"],
                "actor": entry["actor"],
                "description": entry["description"],
                "country": entry.get("country", "ZZ"),
                "city": entry.get("city", "Unknown"),
                "asn": entry.get("asn", "AS00000"),
                "is_tor": entry["category"] == "TOR_EXIT_NODE",
                "enriched_at": datetime.now(timezone.utc).isoformat()
            }
            self.lookup_history.append(result)
            return result

        # 2. Check against suspicious CIDR ranges
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for cidr in SUSPICIOUS_CIDRS:
                if ip_obj in cidr:
                    result = {
                        "ip": ip_str,
                        "is_malicious": True,
                        "threat_score": 75,
                        "category": "SUSPICIOUS_CIDR_PROXY",
                        "actor": "PROXY_PROVIDER",
                        "description": f"IP resides within suspicious subnet {cidr}",
                        "country": "NL",
                        "city": "Unknown",
                        "asn": "AS99999",
                        "is_tor": True,
                        "enriched_at": datetime.now(timezone.utc).isoformat()
                    }
                    self.lookup_history.append(result)
                    return result
        except ValueError:
            pass

        # 3. Private / Internal IP check
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                return {
                    "ip": ip_str,
                    "is_malicious": False,
                    "threat_score": 0,
                    "category": "INTERNAL_NETWORK",
                    "actor": "ENTERPRISE_INTERNAL",
                    "description": "RFC 1918 Private or Loopback address",
                    "country": "INTERNAL",
                    "city": "Corporate Network",
                    "asn": "INTERNAL",
                    "is_tor": False,
                    "enriched_at": datetime.now(timezone.utc).isoformat()
                }
        except ValueError:
            pass

        # 4. Clean / Unknown IP (Default benign external)
        return {
            "ip": ip_str,
            "is_malicious": False,
            "threat_score": 10,
            "category": "CLEAN_EXTERNAL",
            "actor": "NONE",
            "description": "No active malicious indicators found in intelligence feeds",
            "country": "US",
            "city": "Ashburn",
            "asn": "AS16509",
            "is_tor": False,
            "enriched_at": datetime.now(timezone.utc).isoformat()
        }

    def register_custom_ioc(self, ip_str: str, score: int, category: str, actor: str, description: str):
        """Allows SOC analysts or automated feed ingestion to add indicators live."""
        self.ioc_cache[ip_str] = {
            "score": score,
            "category": category,
            "actor": actor,
            "description": description,
            "country": "XX",
            "city": "Custom IoC",
            "asn": "CUSTOM"
        }
        logger.info(f"Registered new threat indicator: {ip_str} ({actor} - {category})")

    def get_feed_summary(self) -> Dict[str, Any]:
        return {
            "total_indicators": len(self.ioc_cache),
            "threat_categories": list(set(e["category"] for e in self.ioc_cache.values())),
            "recent_lookups": self.lookup_history[-10:],
            "active_feeds": [
                {"name": "AlienVault OTX Community Feed", "status": "SYNCED", "indicators": 2400},
                {"name": "AbuseIPDB Verified Attackers", "status": "SYNCED", "indicators": 1850},
                {"name": "The Tor Project Exit List", "status": "SYNCED", "indicators": 890},
                {"name": "Mini-SOC Internal Enterprise IoC DB", "status": "ACTIVE", "indicators": len(self.ioc_cache)}
            ]
        }
