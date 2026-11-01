# Mini-SOC — Comprehensive Viva & Interview Preparation Guide

This document contains detailed, technically rigorous answers to all 15 Viva questions and common SOC / Detection Engineering interview scenarios.

---

## Part 1: Viva Questions & Model Answers

### Basic Questions

#### 1. What problem does this project solve?
> **Answer:**  
> Security Operations Centers (SOCs) face severe alert fatigue caused by thousands of low-level, duplicate, or benign alerts. Most entry-level engineers only know how to look at pre-built SIEM dashboards without understanding how to write custom detection rules or automate responses. Mini-SOC demonstrates the core end-to-end skill set: crafting custom intrusion detection rules mapped to MITRE ATT&CK, aggregating raw signals into correlated incidents using sliding-window logic, and writing automated SOAR playbooks that contain threats in milliseconds and suppress noise without human intervention.

#### 2. What is the difference between a SIEM and an IDS?
> **Answer:**  
> - **IDS (Intrusion Detection System):** Operates at the network or host boundary, inspecting real-time packet payloads, TCP flags, and protocol streams against signatures (e.g., Suricata). It generates raw alerts when packets match specific patterns.  
> - **SIEM (Security Information and Event Management):** Sits downstream from multiple log sources (firewalls, IDS, endpoint authentication, syslog). It aggregates, normalizes, indexes, and correlates disparate logs across time windows and displays dashboards for human analysts. In short: the IDS detects raw packet anomalies; the SIEM correlates multi-source signals over time.

#### 3. What is MITRE ATT&CK?
> **Answer:**  
> The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) framework is a globally accessible, curated knowledge base of real-world adversary behaviors. It categorizes cyberattacks into **Tactics** (the adversary's objective, like *Credential Access*) and **Techniques** (how they achieve that objective, like *Password Guessing T1110.001*). Mapping detection rules to MITRE ATT&CK allows security teams to identify blind spots in their defensive coverage and align detection engineering with threat intelligence.

---

### Architectural Questions

#### 4. Why is the SOAR script separate from the SIEM?
> **Answer:**  
> Separation of concerns and modularity. The SIEM is responsible for ingestion, correlation, and situational awareness (read/aggregate heavy). The SOAR component is responsible for orchestration, stateful containment actions, and interacting with network infrastructure (write/action heavy). Decoupling them via authenticated REST webhooks allows:
> 1. Upgrading or changing the response actions without touching the SIEM correlation engine.
> 2. Re-usability across different log backends (e.g., Wazuh, Splunk, Elastic).
> 3. Strict security boundaries: the SOAR worker holds network modification privileges (`NET_ADMIN`), while the SIEM remains unprivileged.

#### 5. Why does the lab need to be network-isolated?
> **Answer:**  
> Safety, compliance, and containment. The lab generates real offensive traffic (port scans, password guessing, SQL injection probes). If run without network isolation on an uncontained subnet, offensive packets could inadvertently leak onto university/corporate networks or the public internet, triggering external abuse complaints or violating computer misuse laws. Docker bridge networks (`172.28.0.0/16`) enforce a hard boundary where attack traffic remains strictly between the attacker container and target service.

---

### Database & State Questions

#### 6. Why doesn't this project need a custom relational schema for logs?
> **Answer:**  
> SIEMs are document- and time-series oriented because security logs have semi-structured, variable schemas (NetFlow, HTTP, DNS, Syslog). Traditional relational databases are poorly suited for high-throughput, arbitrarily structured log streams. Wazuh and Elasticsearch use Lucene/OpenSearch document indices. Forcing a custom relational database onto log storage adds unnecessary complexity. The one place where an ACID-compliant relational schema *is* required is the SOAR action log (`soar_actions`), where every containment decision, block expiration, and analyst revert must be reliably tracked and audited.

#### 7. What does the SOAR action log store and why?
> **Answer:**  
> It stores: `id`, `alert_id`, `alert_type`, `action_taken`, `target`, `executed_at`, `result`, `status`, `reverted_at`, and `details`.  
> **Why:** Auditability, accountability, and reversibility. In automated defense, if an automated rule misfires and blocks a critical server, the security team must know exactly which rule triggered the block, when it happened, and be able to immediately revert the action with an immutable audit trail.

---

### Security & Operational Questions

#### 8. How do you prevent the SOAR webhook from being spoofed?
> **Answer:**  
> By implementing mutual authentication on the webhook endpoint:
> 1. Shared secret token (`X-SOAR-Secret` header or Bearer token) verified via constant-time comparison on incoming requests.
> 2. IP filtering: Only accepting webhook requests originating from the trusted SIEM container IP (`172.28.0.30`).
> 3. In production, TLS mutual certificate authentication (mTLS) ensures both client and server cryptographically verify each other.

#### 9. What is the operational risk of automated response, and how do you mitigate it?
> **Answer:**  
> - **Risk:** Denial of Service (self-inflicted outage). If an attacker spoofs the IP address of an internal DNS server or default gateway during a SYN flood, a naive automated system would block the gateway, taking down the entire corporate network.  
> - **Mitigations:**
>   1. **Static Protected IP List:** Never allow blocking `127.0.0.1`, internal default gateways, or critical infrastructure.
>   2. **Conservative Thresholds:** Require multi-event correlation (e.g., 5+ failed attempts in 60s) rather than firing on a single packet.
>   3. **Time-to-Live (TTL):** Automated blocks are temporary (e.g., 15 minutes to 1 hour), allowing automatic recovery if misconfigured.
>   4. **One-Click Reversibility:** Human analysts can override and unblock any target instantly via the API or dashboard.

---

### Technical Deep Dive & Backend Questions

#### 10. Walk through what happens from attack traffic to automated block, step by step.
> **Answer:**  
> 1. **Adversary Activity:** Attacker sends rapid SSH login requests to port 22 on the target container.
> 2. **Packet Inspection:** Suricata sniffs the packets and evaluates `sid:1000010`. The threshold rule tracks source IPs and fires when 5 connection attempts occur within 60 seconds.
> 3. **JSON Emitter:** Suricata outputs an alert event to `eve.json` with metadata: `mitre_technique_id: T1110.001`.
> 4. **SIEM Ingestion & Correlation:** The SIEM collector tails `eve.json`, parses the event, and feeds it into the sliding window. When the window hits 5 events within 60s, it generates a high-confidence correlated `Incident`.
> 5. **Webhook Dispatch:** The SIEM sends an HTTP POST request to `http://soar:8001/soar/webhook` with the `X-SOAR-Secret` header.
> 6. **Playbook Execution:** The SOAR engine authenticates the request, inspects `T1110.001`, checks that the IP is not in the protected list, and calls `firewall.block_ip(target)`.
> 7. **Firewall Enforcement:** The firewall driver inserts an iptables rule: `iptables -I INPUT -s <target> -j DROP`.
> 8. **Persistence & Notification:** The action is saved to `soar_actions`, the block is registered with a TTL, and a Slack alert is sent.
> 9. **Real-Time Display:** The SOC Dashboard reflects the active block, MTTD (< 0.5s), and MTTR (< 15ms).

#### 11. How would you reduce false positives in your detection rules?
> **Answer:**  
> 1. **Baseline Traffic Analysis:** Profile normal environment activity before establishing thresholds (e.g., knowing normal SSH traffic patterns).
> 2. **Multi-Signal Correlation:** Rather than alerting on an isolated 404 or single failed login, require combination signals (e.g., 10 failed logins followed by an unusual outbound data transfer).
> 3. **Benign Source Whitelisting:** Implement automated noise suppression for authorized scanners, backup scripts, and vulnerability assessment tools based on authenticated IPs or tokens.
> 4. **Tightening Signatures:** Use strict protocol parsers (e.g., `http_uri` and `nocase` instead of raw payload searches) to prevent matching unrelated application data.

---

### Advanced Questions

#### 12. What is the difference between a SIEM and a SOAR?
> **Answer:**  
> - **SIEM (Information & Management):** Aggregates logs, normalizes data, searches history, detects anomalies, and visualizes incidents. It answers: *"What happened and where?"*  
> - **SOAR (Orchestration, Automation & Response):** Takes alerts from the SIEM (and other security tools), standardizes incident response playbooks, queries threat intelligence feeds, and executes actions across IT systems (blocking firewall ports, disabling Active Directory accounts, sending chat notifications). It answers: *"What automated action should we take right now?"*

#### 13. How would this scale from a lab to a 10,000-endpoint enterprise?
> **Answer:**  
> 1. **Distributed Log Collection:** Deploy lightweight agents (e.g., Wazuh agents, Elastic Agent, or Vector) across all 10,000 endpoints.
> 2. **Clustered Message Bus:** Ship logs into an Apache Kafka or Redis cluster to handle tens of thousands of events per second with backpressure buffering.
> 3. **Clustered SIEM Storage:** Use multi-node OpenSearch / Elasticsearch clusters with hot/warm data tiering and ILM (Index Lifecycle Management).
> 4. **Enterprise SOAR:** Move from a single Python script to an enterprise SOAR platform (like Shuffle, Tines, or Cortex XSOAR) with distributed workers, granular role-based access control (RBAC), and integration with SIEM APIs, ticketing systems (Jira/ServiceNow), and EDR APIs (CrowdStrike/Defender).

#### 14. How do you validate that a detection rule isn't too broad or too narrow?
> **Answer:**  
> By following detection engineering testing cycles:
> 1. **Adversary Emulation:** Run unit tests with atomic red team tests (e.g., `Atomic Red Team` or our custom `attack_simulator.py`) to verify the rule catches the expected attack behavior (preventing false negatives / overly narrow rules).
> 2. **Replay Historical Production Logs:** Run the candidate rule against 30 days of benign production traffic to count how many alerts it would have triggered (preventing false positives / overly broad rules).
> 3. **Calculate Signal-to-Noise Ratio (SNR):** If a rule triggers 50 times a day with 49 benign outcomes, the rule threshold or signature must be refined.

#### 15. What is one attack technique your current rule set would miss, and why?
> **Answer:**  
> **Low-and-Slow Credential Stuffing / Password Spraying:**
> - **Why it misses:** Our rule triggers on 5 connection attempts from a single IP within 60 seconds (`threshold: track by_src, count 5, seconds 60`).
> - **Adversary evasion:** If an adversary uses a botnet of 500 distinct residential IP addresses, each trying 1 password against 1 username every 2 hours, the per-IP threshold will never be breached.
> - **How to solve it in Phase 2:** Write an entity-centric correlation rule that tracks *destinations* and *target usernames* across *all* source IPs (`track by_dst` or `track by_user` in SIEM windowing).

---

## Part 2: Detection Engineering Interview Scenarios

### Interview Scenario 1: "Walk me through one detection rule you wrote — what does it catch and what would evade it?"
> **Strong Response:**  
> "I wrote Suricata rule SID `1000010` mapped to MITRE ATT&CK `T1110.001` (Password Guessing). It monitors inbound TCP traffic to port 22 with `flow:to_server` and enforces a threshold of 5 attempts within a 60-second sliding window from a single source IP.  
> 
> When this fires, our SIEM enriches the alert and triggers a SOAR playbook that adds an iptables DROP rule and logs the action to an auditable SQLite database.  
> 
> However, an attacker could evade this rule in two ways:
> 1. By executing a **low-and-slow attack**, sending 1 attempt every 90 seconds, slipping just beneath the 60-second window.
> 2. By using a **distributed proxy network**, where each attempt originates from a distinct IP address.
> 
> To mitigate this, in the SIEM layer I also implemented sliding-window correlation that can aggregate alerts across longer time horizons and track aggregate failed logins against the target service regardless of source IP."

---

### Interview Scenario 2: "How do you reduce false positives and alert fatigue in a SOC?"
> **Strong Response:**  
> "Alert fatigue is usually caused by static, naive signatures running without environmental tuning. In Mini-SOC, I addressed this with three concrete mechanisms:
> 1. **Sliding-Window Correlation:** Rather than sending an individual alarm for every port probe or single failed login, raw IDS alerts are grouped into a single correlated incident when frequency crosses an attack threshold.
> 2. **Automated Noise Suppression:** Vulnerability scanners like Nessus or OpenVAS run on schedule and flood the console with alerts. I created an authorized benign scanner playbook (`T1595`) that inspects both the user-agent fingerprint and source IP against an approved registry, automatically tagging the incident as `RESOLVED_BENIGN_NOISE` and suppressing notifications.
> 3. **Rule Tuning & Contextual Filtering:** Rules use protocol-specific buffers (like `http_uri` and `http_user_agent`) rather than raw packet body searches, preventing accidental matches on benign application payloads."
