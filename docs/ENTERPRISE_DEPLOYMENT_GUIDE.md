# Mini-SOC Enterprise — Production Deployment & Operations Guide

> **Target Audience:** CTOs, Directors of Information Security, Lead DevSecOps Engineers, and SOC Managers seeking to deploy a self-hosted, sovereign SIEM and SOAR platform for a software company.

---

## 1. Executive Summary & Enterprise Fit

Commercial SIEMs (Splunk, Datadog Cloud SIEM, Panther) charge unpredictable volume-based licensing ($2,000–$10,000+/month) that penalizes engineering teams for verbose debug logs, while open-source tools (raw Wazuh or Elastic) lack automated multi-tier response playbooks out-of-the-box.

**Mini-SOC Enterprise delivers a lightweight, production-grade security operations center tailored for SaaS and engineering organizations:**
- **Zero Ingestion Tax:** Self-hosted on your own AWS/GCP VPC or Kubernetes cluster.
- **Multi-Source Ingestion:** Ingests AWS CloudTrail, Okta Identity, Kubernetes Audit, SaaS Web API logs, and Suricata NIDS.
- **Built-In Threat Intelligence:** Native IP reputation scoring, Tor exit node detection, and GeoIP enrichment (OTX, AbuseIPDB, Tor Project).
- **Multi-Tier SOAR Automation:** Automatically containment across Cloudflare / AWS WAF, Okta identity session revocation, Slack ChatOps, Jira ticketing, and host iptables.
- **Auditor-Ready Compliance:** Pre-mapped controls and automated compliance reports for **AICPA SOC 2 Type II**, **ISO/IEC 27001:2022**, and **PCI-DSS v4.0**.

---

## 2. Infrastructure Architecture Blueprint

```
                      INTERNET / USER TRAFFIC
                                 │
                                 ▼
                     [ Cloudflare / AWS WAF ]
                                 │
                  ┌──────────────┴──────────────┐
                  ▼                             ▼
       [ Production EKS / K8s ]      [ Corporate Identity (Okta) ]
       - Microservices & APIs        - User Logins & MFA Challenges
       - Vector DaemonSet Shipper    - Okta Event Hook Forwarder
                  │                             │
                  └──────────────┬──────────────┘
                                 │ HTTPS / TLS (POST /api/v1/ingest/batch)
                                 ▼
        ┌─────────────────────────────────────────────────────────┐
        │            PRIVATE SECURITY VPC (AWS / GCP)             │
        │                                                         │
        │   ┌─────────────────────────────────────────────────┐   │
        │   │ Mini-SOC SIEM & Ingestion Gateway (Port 8000)   │   │
        │   │ - Dynamic Sigma Rule Evaluator                  │   │
        │   │ - Threat Intel Enrichment (OTX / AbuseIPDB)     │   │
        │   │ - Real-Time Sliding Correlator                  │   │
        │   └────────────────────────┬────────────────────────┘   │
        │                            │ Authenticated Webhook      │
        │                            ▼                            │
        │   ┌─────────────────────────────────────────────────┐   │
        │   │ Mini-SOC SOAR Automation Engine (Port 8001)     │   │
        │   │ - Enterprise Incident Case Management           │   │
        │   │ - Multi-Tier Response Playbooks                 │   │
        │   │ - SQLite / PostgreSQL Action Ledger             │   │
        │   └────────────────────────┬────────────────────────┘   │
        │                            │                            │
        └────────────────────────────┼────────────────────────────┘
                                     │
         ┌───────────────────┬───────┴───────────┬───────────────────┐
         ▼                   ▼                   ▼                   ▼
  [ AWS WAF / CF ]    [ Okta Identity ]    [ Slack Channel ]    [ Jira Service ]
  (Block IPSet)       (Kill Session)       (Interactive Alert)  (Create Ticket)
```

---

## 3. Deployment Options

### Option A: Kubernetes Cluster Deployment (EKS / GKE / AKS)

Deploy directly to your corporate Kubernetes cluster in the `secops` namespace:

```bash
# 1. Clone repository
git clone https://github.com/your-org/mini-soc.git
cd mini-soc

# 2. Configure production secrets in deploy/kubernetes/mini-soc-k8s.yaml
# (Or inject via ExternalSecrets / AWS Secrets Manager)

# 3. Apply manifests
kubectl apply -f deploy/kubernetes/mini-soc-k8s.yaml

# 4. Verify deployment
kubectl get pods -n secops
```

### Option B: Docker Compose on a Dedicated Security Instance (EC2 / Compute Engine)

For small-to-medium software companies seeking dedicated isolation:

1. Provision an **EC2 instance** (`t3.medium` or `t3.large`, Ubuntu 22.04 LTS) in your private security subnet.
2. Ensure Security Group allows inbound port `8000` and `8001` only from internal VPC CIDRs.
3. Clone and start:
   ```bash
   cp .env.example .env
   # Edit .env with your real API tokens
   docker compose up -d --build
   ```

---

## 4. Connecting Corporate Telemetry Sources

### 1. AWS CloudTrail & GuardDuty (5-Minute Setup)
1. In the AWS Console, navigate to **CloudWatch Logs** ➔ select your **CloudTrail Log Group** (e.g. `aws-cloudtrail-logs`).
2. Go to **Subscription Filters** ➔ click **Create Lambda subscription filter**.
3. Deploy the Lambda script provided in [`deploy/aws/cloudwatch_lambda_shipper.py`](../deploy/aws/cloudwatch_lambda_shipper.py).
4. Set environment variables:
   - `MINI_SOC_ENDPOINT`: `https://soc.company.internal/api/v1/ingest/batch`
   - `MINI_SOC_API_KEY`: Your configured ingest bearer token.
5. Save the filter. All CloudTrail logs (root logins, IAM changes, S3 modifications) now stream into Mini-SOC automatically.

### 2. Okta Identity & Single Sign-On (5-Minute Setup)
1. In Okta Admin Console, navigate to **Workflow** ➔ **Event Hooks**.
2. Click **Create Event Hook**:
   - **Name:** `Mini-SOC Identity Telemetry`
   - **URL:** `https://soc.company.internal/okta/events` (pointing to [`deploy/okta/okta_webhook_handler.py`](../deploy/okta/okta_webhook_handler.py))
   - **Authentication field:** `Authorization`
   - **Authentication secret:** `Bearer <MINI_SOC_API_KEY>`
3. Subscribe to events:
   - `user.session.start`
   - `user.authentication.verify`
   - `user.mfa.verify_push`
4. Click **Verify**. The handler executes Okta's one-time challenge handshake, and live MFA fatigue / brute-force events will flow in real-time.

### 3. Application Microservices & Nginx (Vector DaemonSet)
Deploy **Vector** across your Kubernetes cluster using the configuration provided in [`deploy/vector/vector.yaml`](../deploy/vector/vector.yaml):
- Collects container stdout/stderr, access logs, and 500 error spikes.
- Formats payloads into Mini-SOC's universal schema and batches them over HTTP POST.

---

## 5. Automated Response Playbooks Configuration

Mini-SOC Enterprise comes pre-configured with multi-tier automated playbooks:

### 1. Cloud Perimeter Block (AWS WAF & Cloudflare)
- **When triggered:** SQL injection (`T1190`), Cloud Metadata SSRF (`T1552.005`), or Known C2 IP match.
- **Action:** Calls AWS WAF API to append the malicious IP to the active WAF IPSet, or calls Cloudflare Firewall API to create a dynamic IP Access Rule with a 1-hour expiration.

### 2. Identity Session Revocation (Okta / Auth0)
- **When triggered:** High-velocity MFA push fatigue (`T1621`) or brute-force compromise.
- **Action:** Calls Okta `/api/v1/users/{userId}/sessions` to terminate all active sessions, prompts the user for password reset, and notifies the SecOps Slack channel.

### 3. ChatOps & SecOps Escalation (Slack & Jira)
- **Slack Block Kit:** Sends interactive cards to `#secops-alerts` with incident details and triage buttons ("Quarantine Host", "Acknowledge", "Mark False Positive").
- **Jira Automation:** Automatically creates a Jira Service Management ticket with reproduction details and sets SLA timers according to severity (P1 = 15m, P2 = 60m).

---

## 6. Passing SOC 2 Type II & Compliance Audits

Mini-SOC directly satisfies the most scrutinized criteria during a **SOC 2 Type II Security & Availability audit**:

| SOC 2 Trust Criteria | What Auditors Ask For | How Mini-SOC Proves Compliance |
|---|---|---|
| **CC6.1 / CC6.6** | Evidence of perimeter boundary protection and threat containment | Immutable log of automated firewall drops and Cloud WAF blocks in `soar_actions` table. |
| **CC7.2** | Evidence of continuous security monitoring and anomaly detection | Multi-source event ingestion stream, active Suricata NIDS inspection, and sliding-window correlation. |
| **CC7.3** | Formal security incident evaluation and triage workflows | Case management records in `soar_cases` showing severity ranking, analyst assignment, and MTTA/MTTR. |
| **CC7.4** | Incident remediation audit trail and reversibility | Audit trail in `audit_logs` tracking every unblock, analyst note, and ticket reference with cryptographic timestamps. |

> 📄 **Instant Audit Assessment:** Navigate to the **SOC 2 & Compliance Audit** tab in the Web Dashboard or call `GET /api/compliance/soc2` to generate an executive compliance report for auditors in one click.

---

## 7. Operations & Maintenance Runbook

- **Testing Alerting:** Run `python lab/attacker/attack_simulator.py demo` from a staging environment to generate synthetic test events.
- **Adding Custom Sigma Rules:** Add `.yml` files to `sigma-rules/` or post new rules via `POST /api/sigma/rules`—they reload dynamically without service interruption.
- **Backups:** Schedule daily snapshots of `soar_actions.db` (or point `SOAR_DB_PATH` to an Amazon RDS PostgreSQL instance via standard SQLAlchemy driver).
- **Log Retention:** By default, in-memory buffers store the last 5,000 events, while persistent cases and audit logs are retained indefinitely.
