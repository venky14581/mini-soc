# Mini-SOC System Architecture & Engineering Design

---

## 1. High-Level Architecture Diagram

```
+-----------------------------------------------------------------------------------+
|                           ISOLATED LAB NETWORK (172.28.0.0/16)                    |
|                                                                                   |
|  +-------------------------+                     +-----------------------------+  |
|  |   Attacker Lab Client   |-------------------->|   Lab Target Service        |  |
|  |   (Nmap, Hydra, Python) |  Network Traffic    |   (SSH: 22, HTTP: 8080)     |  |
|  +-------------------------+                     +-----------------------------+  |
|                                                                 |                 |
|                                                       Tapped / Sniffed            |
|                                                                 v                 |
|                                                  +-----------------------------+  |
|                                                  |   Suricata Network IDS      |  |
|                                                  |   (Custom MITRE Rules)      |  |
|                                                  +-----------------------------+  |
|                                                                 |                 |
|                                                       JSON Alerts (eve.json)      |
|                                                                 v                 |
|  +-----------------------------------------------------------------------------+  |
|  |   Mini-SOC SIEM & Correlation Engine (Port 8000)                            |  |
|  |   - Sliding Window Aggregator (e.g., 5 alerts in 60s -> Incident)           |  |
|  |   - MITRE ATT&CK Enterprise Matrix Mapper                                   |  |
|  |   - SOC Analyst Web Dashboard & Query Interface                             |  |
|  +-----------------------------------------------------------------------------+  |
|                                           |                                       |
|                                Authenticated Webhook                              |
|                          (Header: X-SOAR-Secret, Port 8001)                       |
|                                           v                                       |
|  +-----------------------------------------------------------------------------+  |
|  |   Mini-SOC SOAR Automation Engine (Port 8001)                               |  |
|  |   - Secret Verification & Token Auth                                        |  |
|  |   - Automated Playbook Dispatcher                                           |  |
|  |   - SQLite Action Persistence (soar_actions table)                          |  |
|  |   - Firewall Driver (iptables / containment)                                |  |
|  |   - Notification Gateway (Slack / Webhooks)                                 |  |
|  +-----------------------------------------------------------------------------+  |
|          |                                   |                            |       |
|          v                                   v                            v       |
|  [ iptables DROP ]                 [ Slack Rich Alert ]          [ Noise Suppress ]
+-----------------------------------------------------------------------------------+
```

---

## 2. Event Correlation Pipeline & Data Flow

1. **Traffic Generation:** The attacker client targets port 22 or port 8080 on the vulnerable lab target.
2. **Packet Inspection:** Suricata sniffs the traffic on the bridge interface and compares packet headers, TCP flags, and payload strings against `suricata/rules/local.rules`.
3. **Structured Alerting:** When a signature matches, Suricata writes a structured JSON event to `eve.json` containing metadata, community-id, IP addresses, and custom SID.
4. **Log Ingestion & Enrichment:** The SIEM collector tails `eve.json` and enriches each record with MITRE ATT&CK tactic/technique details and severity ratings.
5. **Sliding-Window Correlation:**
   - Raw alerts are pushed to per-IP and per-technique sliding windows.
   - If threshold conditions are met (e.g. 5 SSH login failures within 60 seconds), a correlated `Incident` is generated, cutting alert fatigue.
6. **SOAR Webhook Trigger:** The SIEM sends an authenticated HTTP POST payload to `/soar/webhook` with the header `X-SOAR-Secret`.
7. **Playbook Execution:**
   - **SSH Brute Force / Web Attack:** The SOAR engine blocks the offending IP via `iptables -I INPUT -s <target> -j DROP`, registers the block with an expiration TTL, and notifies the analyst.
   - **Authorized Benign Scanner:** If the source IP matches the internal audit whitelist, the SOAR engine tags the alert as `RESOLVED_BENIGN_NOISE`, skips blocking, and logs the suppression.
8. **Auditing & Reversibility:** Every action is committed to SQLite `soar_actions`. Analysts can inspect the action log on the Web Dashboard and click "Revert" to immediately restore firewall connectivity.

---

## 3. Database Schema (Section 13)

SQLite persistence is maintained in `soar_actions.db`:

```sql
CREATE TABLE soar_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    action_taken TEXT NOT NULL,
    target TEXT NOT NULL,
    executed_at TEXT NOT NULL,
    result TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ACTIVE',
    reverted_at TEXT,
    details TEXT
);

CREATE TABLE active_blocks (
    target TEXT PRIMARY KEY,
    action_id INTEGER,
    reason TEXT,
    blocked_at TEXT NOT NULL,
    expires_at TEXT,
    FOREIGN KEY(action_id) REFERENCES soar_actions(id)
);

CREATE TABLE benign_whitelist (
    ip_or_subnet TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    added_at TEXT NOT NULL
);
```

---

## 4. Threat Model & Mitigations

| Threat | Attack Vector | Security Impact | Mitigation Implemented |
|---|---|---|---|
| **Webhook Spoofing** | Attacker injects fake alerts to `/soar/webhook` | Causes false automated IP blocks | Shared secret header `X-SOAR-Secret` and Bearer token verification |
| **Denial of Service via False Positive** | Attacker spoofs source IP of gateway or legitimate servers | Legitimate services blocked by automated response | Static `PROTECTED_IPS` guard list prevents blocking `127.0.0.1`, gateways, and local subnets |
| **Scope Creep / Out-of-bounds traffic** | Offensive tools target external internet | Unauthorized external scanning | Strict Docker bridge network isolation (`172.28.0.0/16`) without external routing |
| **Overly Aggressive Auto-Blocks** | Legitimate user locked out after accidental typos | Availability loss | Time-to-Live (TTL) expiration on blocks + one-click analyst manual revert endpoint |
