# Mini-SOC — MITRE ATT&CK® Detection & Response Matrix

This document provides a comprehensive mapping between Mini-SOC custom detection rules, the MITRE ATT&CK enterprise matrix, evasion vectors, and automated SOAR response playbooks.

---

## 1. Matrix Overview

| MITRE Tactic | Technique ID | Technique Name | Suricata SID | Sigma Rule | Automated SOAR Action |
|---|---|---|---|---|---|
| **TA0007: Discovery** | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Scanning | `1000001` - `1000005` | `nmap_port_scan.yml` | `CONTAIN_SCANNER` (15m firewall drop) |
| **TA0006: Credential Access** | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | Password Guessing (SSH Brute Force) | `1000010`, `1000011` | `ssh_brute_force.yml` | `BLOCK_IP` (iptables DROP + Slack alert) |
| **TA0001: Initial Access** | [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application (SQLi) | `1000020`, `1000021` | `web_sql_injection.yml` | `BLOCK_IP` (Immediate host isolation) |
| **TA0007: Discovery** | [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery (Path Traversal) | `1000022`, `1000023` | `web_directory_traversal.yml` | `BLOCK_IP` (Immediate host isolation) |
| **TA0002: Execution** | [T1059](https://attack.mitre.org/techniques/T1059/) | Command & Scripting Interpreter (Web Shell / RCE) | `1000030`, `1000031` | `reverse_shell_probe.yml` | `BLOCK_IP` + Escalation Alert |
| **TA0043: Reconnaissance** | [T1595.002](https://attack.mitre.org/techniques/T1595/002/) | Vulnerability Scanning (Nikto, sqlmap, Gobuster) | `1000040` - `1000042` | `web_scanner_nikto_sqlmap.yml` | `CONTAIN_SCANNER` |
| **TA0043: Reconnaissance** | [T1595](https://attack.mitre.org/techniques/T1595/) | Active Scanning (Authorized Internal Audit) | `1000050` | `benign_vulnerability_scanner.yml` | `AUTO_TAG_NOISE` (Suppression / No block) |

---

## 2. Detailed Technique Analysis

### Technique: T1046 — Network Service Scanning
- **Description:** Adversaries probe open TCP/UDP ports across network services to discover running services and potential entry points.
- **Detection Logic:** 
  - Suricata flags inspection: `flags:S` with `window:1024` (Nmap SYN scan signature), `flags:0,12` (NULL scan), `flags:FPU,12` (XMAS scan), `flags:F,12` (FIN scan).
  - Multi-port threshold filter: `count 10, seconds 5; track by_src`.
- **Evasion Vectors:** Slow, distributed port scanning (e.g. `nmap -T1` or `nmap -T0` sending probes minutes apart) or scanning via rotating proxy pools.
- **SOAR Response:** Attacker IP is dynamically placed in temporary firewall quarantine (`CONTAIN_SCANNER`) for 15 minutes.

---

### Technique: T1110.001 — Password Guessing (SSH Brute Force)
- **Description:** Adversaries systematically submit passwords against known or suspected usernames to gain valid credentials.
- **Detection Logic:** 
  - Monitored port: TCP 22 / SSH.
  - Threshold rule: `count 5, seconds 60; track by_src`.
  - SIEM correlation: Sliding window aggregates multiple failed authentication attempts within 60s into a high-confidence `INC-SSH-BRUTEFORCE` incident.
- **Evasion Vectors:** "Low and slow" brute-force (1 attempt every 2 minutes) or password spraying (1 single password tried across hundreds of different usernames to evade lockout thresholds).
- **SOAR Response:** Attacker IP is immediately blocked on firewall via `iptables -I INPUT -s <target> -j DROP`, Slack alert dispatched, and incident recorded with full reversibility.

---

### Technique: T1190 — Exploit Public-Facing Application
- **Description:** Adversaries attempt to exploit vulnerabilities in Internet-accessible software (SQL injection, Log4j JNDI, unauthenticated RCE).
- **Detection Logic:**
  - HTTP URI and Body inspection for keywords: `UNION SELECT`, `' OR '1'='1`, `${jndi:`.
- **Evasion Vectors:** URL encoding (`%55%4e%49%4f%4e`), SQL comment tricks (`UNI/**/ON SELECT`), or POST body payload obfuscation.
- **SOAR Response:** Instant host drop via firewall driver and critical triage escalation.

---

### Technique: T1083 — File and Directory Discovery
- **Description:** Adversaries navigate file systems via directory traversal (`../`) seeking sensitive files like `/etc/passwd` or configuration tokens.
- **Detection Logic:**
  - Content match on URI for `../`, `../../`, and `/etc/passwd`.
- **Evasion Vectors:** Double URL encoding (`%252e%252e%252f`), Unicode normalization quirks, or path truncation.
- **SOAR Response:** Automatic containment and alert audit logging.

---

### Technique: T1595 — Active Scanning (Benign Noise Suppression)
- **Description:** Internal IT and SecOps teams periodically run authorized vulnerability assessments (e.g., Nessus, OpenVAS, MiniSOC-AuditScanner).
- **The Operational Problem:** Low-quality SOC workflows generate dozens of false-positive alarms every night when the internal scanner runs, wasting analyst hours.
- **Mini-SOC Solution:** 
  - Dual-factor validation: User-Agent fingerprint + IP whitelist check (`172.28.0.254`).
  - SOAR automatically executes `AUTO_TAG_NOISE`, marks the alert as `RESOLVED_BENIGN`, suppresses notification spam, and keeps the audit trail clean.
