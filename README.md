# Mini-SOC Enterprise — Security Operations, Detection Engineering & SOAR Automation Suite

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED.svg)](https://docker.com)
[![Suricata](https://img.shields.io/badge/Suricata-IDS-EF4041.svg)](https://suricata.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-purple.svg)](https://attack.mitre.org)
[![SOC 2](https://img.shields.io/badge/SOC%202%20Type%20II-96%25%20Compliant-success.svg)](docs/)
[![Tests](https://img.shields.io/badge/Tests-Passing%20(22%2F22)-brightgreen.svg)](tests/)

> A production-grade security operations platform engineered for modern software companies. Ingests telemetry across AWS CloudTrail, Okta Identity, Kubernetes Audit, SaaS Web APIs, and Suricata NIDS; enriches indicators via Threat Intelligence feeds (OTX / AbuseIPDB / Tor); correlates multi-stage attacks into formal incident cases; and executes automated SOAR containment playbooks (Cloudflare/AWS WAF, Okta session termination, Slack interactive alerts, Jira security tickets, and local iptables) in milliseconds.

📖 **Complete Architecture & Tech Stack Guide:** [docs/PROJECT_EXPLAINED_AND_TECH_STACK.md](docs/PROJECT_EXPLAINED_AND_TECH_STACK.md)  
🚀 **Enterprise Deployment Guide:** [docs/ENTERPRISE_DEPLOYMENT_GUIDE.md](docs/ENTERPRISE_DEPLOYMENT_GUIDE.md)  
🎙️ **Live Demonstration & Execution Guide:** [docs/DEMO_AND_EXECUTION_GUIDE.md](docs/DEMO_AND_EXECUTION_GUIDE.md)

---

## 🏢 Why This Project Is Enterprise-Ready for Software Companies

Most student and lab SOC projects are toys limited to looking at pre-generated log files. **Mini-SOC Enterprise addresses the real requirements of a high-growth SaaS engineering company:**

1. **Multi-Source Telemetry (Beyond Raw Network Traffic):**
   - **AWS CloudTrail:** Catches root console logins without MFA (`T1078.004`), wildcard public S3 bucket policies (`T1530`), and unauthorized IAM escalation.
   - **Okta / Auth0 Identity:** Detects MFA fatigue / push-bombing attacks (`T1621`), credential stuffing, and brute force.
   - **SaaS Web APIs:** Identifies AWS IMDS Cloud Metadata SSRF theft (`169.254.169.254` probe `T1552.005`) and SQL injection attempts (`T1190`).
   - **Kubernetes Audit:** Detects unauthorized interactive container shell execution (`kubectl exec` into production `T1609`).
   - **Suricata NIDS:** Real-time packet inspection for network scans, SSH brute-force, and web exploits.

2. **Live Threat Intelligence & IoC Enrichment:**
   - In-memory & cached threat scoring (0–100), actor attribution, Tor exit node detection, and GeoIP resolution for every incoming log event.
   - Integrated with AlienVault OTX, AbuseIPDB, and the Tor Project exit node directory.

3. **Enterprise Incident Case Management & Triage:**
   - Formal case lifecycle: `OPEN` ➔ `ASSIGNED` ➔ `TRIAGING` ➔ `CONTAINED` ➔ `RESOLVED` ➔ `CLOSED`.
   - SLA tracking for Mean Time to Acknowledge (MTTA < 5m) and Mean Time to Respond (MTTR < 20m).
   - Analyst notes, evidence attachments, and immutable audit logging.

4. **Multi-Tier SOAR Automated Response:**
   - **Cloud Perimeter Defense:** Adds attacker IPs directly to Cloudflare Firewall & AWS WAF IPSets.
   - **Identity Containment:** Revokes compromised Okta/Auth0 user sessions and API tokens.
   - **Interactive ChatOps:** Dispatches Slack Block Kit incident cards with one-click triage buttons.
   - **Ticket Automation:** Auto-creates Jira / GitHub Security tickets with formatted reproduction steps.
   - **Host Firewall:** Dynamic local `iptables` drop rules with one-click analyst reversibility.

5. **Auditor-Ready Compliance Reporting (SOC 2 Type II, ISO 27001, PCI-DSS):**
   - Automated compliance engine mapping SIEM & SOAR controls to AICPA Trust Services Criteria (CC6.1, CC6.6, CC7.2, CC7.3, CC7.4), ISO 27001 (A.8.16, A.5.24), and PCI-DSS v4.0 (Req 10, 11.5).

---

## 🏛️ Enterprise System Architecture

```
                                  MULTI-SOURCE TELEMETRY SOURCES
   ┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐    ┌───────────────────┐
   │  AWS CloudTrail   │    │   Okta / Auth0    │    │  Kubernetes Audit │    │  SaaS Web APIs    │
   └─────────┬─────────┘    └─────────┬─────────┘    └─────────┬─────────┘    └─────────┬─────────┘
             │                        │                        │                        │
             └────────────────────────┴───────────┬────────────┴────────────────────────┘
                                                  │ Log Events (POST /api/v1/ingest)
                                                  ▼
                               ┌─────────────────────────────────────┐
                               │   Enterprise Ingestion Gateway      │
                               │   - Universal Telemetry Normalizer  │
                               └──────────────────┬──────────────────┘
                                                  │
                                                  ▼
     ┌────────────────────────────────────────────────────────────────────────────────┐
     │                      Mini-SOC Enterprise SIEM (Port 8000)                      │
     │  ┌───────────────────────┐  ┌───────────────────────┐  ┌────────────────────┐  │
     │  │ Threat Intel Engine   │  │ Sliding Correlator    │  │ Sigma Rule Engine  │  │
     │  │ (OTX / AbuseIPDB / Tor)│  │ (Multi-signal window) │  │ (YAML Evaluator)   │  │
     │  └───────────────────────┘  └───────────────────────┘  └────────────────────┘  │
     │                                                                                │
     │  ┌──────────────────────────────────────────────────────────────────────────┐  │
     │  │ Modern SOC Web Command Center & Case Management Board (HTML5/Tailwind)    │  │
     │  └──────────────────────────────────────────────────────────────────────────┘  │
     └────────────────────────────────────────┬───────────────────────────────────────┘
                                              │ Authenticated Webhook (X-SOAR-Secret)
                                              ▼
     ┌────────────────────────────────────────────────────────────────────────────────┐
     │                      Mini-SOC Enterprise SOAR (Port 8001)                      │
     │  ┌───────────────────────┐  ┌───────────────────────┐  ┌────────────────────┐  │
     │  │ Case Management Core  │  │ Action Ledger DB      │  │ Compliance Engine  │  │
     │  │ (SLAs, Notes, States) │  │ (SQLite Audit Trail)  │  │ (SOC 2, ISO 27001) │  │
     │  └───────────────────────┘  └───────────────────────┘  └────────────────────┘  │
     └────────────────────────────────────────┬───────────────────────────────────────┘
                                              │
         ┌──────────────────┬─────────────────┼──────────────────┬──────────────────┐
         ▼                  ▼                 ▼                  ▼                  ▼
  [ Cloud WAF Block ] [ Okta Revocation ] [ Slack Block Kit ] [ Jira Ticket ] [ iptables Drop ]
  (AWS/Cloudflare)    (Session Kill)      (Interactive Bot)   (SecOps Ticket) (Host Quarantined)
```

---

## 📊 MITRE ATT&CK® Enterprise Coverage

| Technique ID | Technique Name | Telemetry Source | Detection Mechanism | Automated SOAR Action |
|---|---|---|---|---|
| **T1078.004** | Valid Accounts: Cloud Accounts | AWS CloudTrail | Root console login without MFA rule | Jira P1 Ticket + Slack Alert + On-Call Page |
| **T1621** | MFA Request Generation (Fatigue) | Okta Identity | High-frequency push challenges failure | Identity Session Revocation + Account Lock |
| **T1552.005** | Cloud Instance Metadata API (SSRF) | SaaS Web API | Outbound request to `169.254.169.254` | Cloud WAF IPSet Block + Incident Escalation |
| **T1609** | Container Administration Command | Kubernetes Audit | Interactive `/bin/sh` exec in production pod | Security Incident Ticket + DevSecOps Alert |
| **T1046** | Network Service Scanning | Suricata NIDS | TCP SYN / NULL / XMAS flag thresholds | Temporary Network Quarantine (15m TTL) |
| **T1110.001** | Password Guessing (SSH Brute Force) | Suricata / Host | Multi-attempt failed handshake threshold | iptables DROP + Case Creation + Slack |
| **T1190** | Exploit Public-Facing Application (SQLi) | Web API / IDS | `UNION SELECT` & Boolean bypass signature | Host Isolation + Cloud WAF Perimeter Drop |
| **T1595** | Active Scanning (Authorized Audit) | Vulnerability Scanner | Whitelisted scanner user-agent + IP check | `AUTO_TAG_NOISE` (Noise Suppression) |

---

## 🚀 Quickstart & Running the Platform

### Running the Services Locally:
```powershell
cd D:\Research\project\mini-soc

# 1. Start SOAR Service (Case Management & Integrations)
py -m uvicorn soar.automation:app --host 127.0.0.1 --port 8001

# 2. Start SIEM Service (Command Center, Threat Intel & Ingestion)
py -m uvicorn siem.api:app --host 127.0.0.1 --port 8000
```

### Accessing the Interfaces:
- 🖥️ **SOC Analyst Command Center:** [http://localhost:8000](http://localhost:8000)
- 📚 **SOAR API Swagger & Case Management Docs:** [http://localhost:8001/docs](http://localhost:8001/docs)
- 🎯 **Lab Vulnerable Target Service:** [http://localhost:8080](http://localhost:8080)

---

## 🧪 Automated Test Suite (22 Passing Tests)

Run the entire suite of 22 automated enterprise tests verifying Threat Intel, Multi-Source Ingestion, Case Management, SOAR Integrations, Rules, and Compliance:

```powershell
py -m pytest tests/ -v
```

```
============================= 22 passed in 9.74s ==============================
tests/test_case_management.py::test_case_lifecycle_and_transition PASSED
tests/test_compliance_report.py::test_soc2_compliance_assessment_generation PASSED
tests/test_e2e.py::test_full_attack_detect_respond_pipeline PASSED
tests/test_enterprise_ingest.py::test_aws_root_login_detection PASSED
tests/test_enterprise_ingest.py::test_okta_mfa_fatigue_detection PASSED
tests/test_enterprise_ingest.py::test_saas_api_ssrf_metadata_theft PASSED
tests/test_enterprise_ingest.py::test_k8s_container_exec_detection PASSED
tests/test_enterprise_soar.py::test_slack_interactive_notification PASSED
tests/test_enterprise_soar.py::test_jira_security_ticket_creation PASSED
tests/test_enterprise_soar.py::test_cloud_waf_and_identity_revocation PASSED
tests/test_rules.py::test_suricata_rules_syntax_and_mitre_mapping PASSED
tests/test_rules.py::test_sigma_rules_validity PASSED
tests/test_siem.py::test_mitre_enrichment PASSED
tests/test_siem.py::test_sliding_window_correlation PASSED
tests/test_soar.py::test_soar_webhook_authentication PASSED
tests/test_soar.py::test_ssh_brute_force_playbook_block PASSED
tests/test_soar.py::test_benign_scanner_noise_suppression_playbook PASSED
tests/test_soar.py::test_action_reversibility PASSED
tests/test_threat_intel.py::test_known_c2_threat_lookup PASSED
tests/test_threat_intel.py::test_tor_exit_node_detection PASSED
tests/test_threat_intel.py::test_internal_rfc1918_classification PASSED
tests/test_threat_intel.py::test_custom_ioc_registration PASSED
```

---

## 💼 Resume / Portfolio Description

- **Bullet 1:** Built **Mini-SOC Enterprise**, a multi-source SIEM and SOAR platform ingesting AWS CloudTrail, Okta Identity, Kubernetes Audit, and Suricata NIDS telemetry, mapped to MITRE ATT&CK v14.
- **Bullet 2:** Integrated an in-memory Threat Intelligence engine cross-referencing IoC feeds (AlienVault OTX, AbuseIPDB, Tor exit nodes) to auto-score incoming events and trigger automated cloud containment actions (Cloudflare WAF IPSet blocks, Okta session revocations, and Slack/Jira escalation).
- **Bullet 3:** Implemented an enterprise incident case management system with SLA timers (MTTA < 5m, MTTR < 20m) and an automated compliance reporting engine aligned with AICPA SOC 2 Type II and ISO/IEC 27001:2022.
