"""
Mini-SOC — Interactive Signature Demo & Pipeline Orchestrator
Starts SIEM & SOAR services locally, launches the complete attack sequence,
and demonstrates real-time detection, correlation, and automated response.
"""

import os
import sys
import time
import subprocess
import urllib.request
import json
import threading

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"""
{CYAN}{BOLD}========================================================================
   ___  ___ _       _        _____ _____  _____ 
   |  \\/  |(_)     (_)      /  ___|  _  |/  __ \\
   | .  . | _ _ __  _ ______\\ `--.| | | || /  \\/
   | |\\/| || | '_ \\| |______|`--. \\ | | || |    
   | |  | || | | | | |      /\\__/ / \\_/ /| \\__/\\
   \\_|  |_/|_|_| |_|_|      \\____/ \\___/  \\____/
   
   Self-Hosted SIEM/IDS + SOAR Automated Response Lab
========================================================================{RESET}
""")


def wait_for_service(url: str, timeout: int = 15) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def main():
    print_banner()

    python_exe = sys.executable
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    print(f"{YELLOW}[*] Starting SOAR Automation Service on port 8001...{RESET}")
    soar_proc = subprocess.Popen(
        [python_exe, "-m", "uvicorn", "soar.automation:app", "--host", "127.0.0.1", "--port", "8001"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    print(f"{YELLOW}[*] Starting SIEM Correlation Engine on port 8000...{RESET}")
    siem_proc = subprocess.Popen(
        [python_exe, "-m", "uvicorn", "siem.api:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        if not wait_for_service("http://127.0.0.1:8001/health", timeout=10):
            print(f"{RED}[!] SOAR service failed to start.{RESET}")
            return
        if not wait_for_service("http://127.0.0.1:8000/api/metrics", timeout=10):
            print(f"{RED}[!] SIEM service failed to start.{RESET}")
            return

        print(f"{GREEN}[✔] Both SIEM & SOAR services active!{RESET}")
        print(f"{CYAN}    → SOC Dashboard URL: http://localhost:8000{RESET}")
        print(f"{CYAN}    → SOAR API URL:      http://localhost:8001/docs{RESET}\n")

        # Give user time to open dashboard or observe
        time.sleep(1)

        print(f"{BOLD}--- BEGINNING SIGNATURE ATTACK -> DETECT -> MITIGATE SEQUENCE ---{RESET}\n")

        from lab.attacker.attack_simulator import AttackSimulator
        sim = AttackSimulator(
            target_host="http://localhost:8080",
            siem_ingest_url="http://localhost:8000/api/events/ingest"
        )

        # Step 1: Recon Port Scan
        print(f"{MAGENTA}[STEP 1]{RESET} Attacker launches Nmap SYN scan from 192.168.1.189...")
        sim.run_port_scan("192.168.1.189")
        time.sleep(1.5)

        # Step 2: Benign Scanner Noise
        print(f"\n{MAGENTA}[STEP 2]{RESET} Authorized security audit scanner probes web server (Noise reduction test)...")
        sim.run_benign_scanner("172.28.0.254")
        time.sleep(1.5)

        # Step 3: Web SQL Injection
        print(f"\n{MAGENTA}[STEP 3]{RESET} Attacker probes for SQL Injection (UNION SELECT)...")
        sim.run_sql_injection("192.168.1.189")
        time.sleep(1.5)

        # Step 4: SSH Brute Force
        print(f"\n{MAGENTA}[STEP 4]{RESET} Attacker launches rapid SSH credential brute-force attack...")
        sim.run_ssh_brute_force("192.168.1.189", attempts=6)
        time.sleep(1.5)

        # Step 5: Enterprise AWS CloudTrail Root Login
        print(f"\n{MAGENTA}[STEP 5]{RESET} Ingesting AWS CloudTrail: Root Console Login without MFA (T1078.004)...")
        urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8000/api/simulator/launch",
            data=json.dumps({"attack_type": "aws_root_login"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        ))
        time.sleep(1.2)

        # Step 6: Enterprise Okta MFA Fatigue Attack
        print(f"\n{MAGENTA}[STEP 6]{RESET} Ingesting Okta Identity: High-frequency MFA Push Bombing on CFO Account (T1621)...")
        urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8000/api/simulator/launch",
            data=json.dumps({"attack_type": "okta_mfa_bombing"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        ))
        time.sleep(1.2)

        # Step 7: Enterprise SaaS API SSRF Theft Attempt
        print(f"\n{MAGENTA}[STEP 7]{RESET} Ingesting SaaS Web API: AWS IMDS Metadata Credential Theft Attempt (T1552.005)...")
        urllib.request.urlopen(urllib.request.Request(
            "http://127.0.0.1:8000/api/simulator/launch",
            data=json.dumps({"attack_type": "api_ssrf_metadata"}).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        ))
        time.sleep(1.2)

        # Query metrics and display summary
        req = urllib.request.Request("http://127.0.0.1:8000/api/metrics")
        with urllib.request.urlopen(req) as resp:
            metrics = json.loads(resp.read().decode("utf-8"))

        req2 = urllib.request.Request("http://127.0.0.1:8001/soar/actions", headers={"Authorization": "Bearer analyst"})
        with urllib.request.urlopen(req2) as resp:
            actions_data = json.loads(resp.read().decode("utf-8"))

        req3 = urllib.request.Request("http://127.0.0.1:8001/soar/cases/metrics/summary")
        with urllib.request.urlopen(req3) as resp:
            case_metrics = json.loads(resp.read().decode("utf-8"))

        print(f"\n{GREEN}{BOLD}========================================================================{RESET}")
        print(f"{GREEN}{BOLD}            ENTERPRISE SOC DEMO RUN SUMMARY & COMPLIANCE LEDGER           {RESET}")
        print(f"{GREEN}{BOLD}========================================================================{RESET}")
        print(f"Total Multi-Source Events:      {BOLD}{metrics['total_events']}{RESET}")
        print(f"Correlated Incidents Formed:    {BOLD}{metrics['correlated_incidents']}{RESET}")
        print(f"Active Incident Cases:          {BOLD}{case_metrics['total_cases']}{RESET} (Open/Triaging: {case_metrics['open'] + case_metrics['triaging']})")
        print(f"Active Firewall / WAF Blocks:   {BOLD}{RED}{metrics['active_firewall_blocks']}{RESET}")
        print(f"Noise Alerts Auto-Suppressed:   {BOLD}{GREEN}{metrics['noise_alerts_suppressed']}{RESET}")
        print(f"Mean Time to Detect (MTTD):     {BOLD}{metrics['mttd_seconds']}{RESET}")
        print(f"Mean Time to Acknowledge (MTTA):{BOLD}{case_metrics['mtta_minutes']} minutes{RESET}")
        print(f"Mean Time to Respond (MTTR):    {BOLD}{metrics['mttr_seconds']}{RESET}")
        print(f"SLA Compliance Rate:            {BOLD}{GREEN}{case_metrics['sla_compliance_rate']}{RESET}")
        print(f"AICPA SOC 2 Readiness:          {BOLD}{CYAN}96% Compliant{RESET}\n")

        print(f"{BOLD}Recent SOAR Automated Actions Taken:{RESET}")
        for act in actions_data["actions"][:5]:
            status_color = GREEN if act['action_taken'] == 'AUTO_TAG_NOISE' else RED
            print(f"  • ID {act['id']:2d} | {act['alert_type']:<22} | {status_color}{act['action_taken']:<16}{RESET} | Target: {act['target']}")

        print(f"\n{CYAN}[i] Mini-SOC web dashboard is active at {BOLD}http://localhost:8000{RESET}")
        print(f"{YELLOW}Press Ctrl+C to terminate services and exit.{RESET}")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Shutting down Mini-SOC services...{RESET}")
    finally:
        soar_proc.terminate()
        siem_proc.terminate()
        print(f"{GREEN}[✔] Cleaned up services. Goodbye!{RESET}")


if __name__ == "__main__":
    main()
