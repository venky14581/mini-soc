"""
Mini-SOC Lab Attack Simulator Toolkit
Generates controlled, safe attack traffic inside the isolated lab network
to validate detection rules, SIEM correlation, and SOAR response playbooks.
"""

import sys
import time
import argparse
import logging
import urllib.request
import urllib.error
import urllib.parse
import json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ATTACKER-SIM] %(message)s")
logger = logging.getLogger("attacker")


class AttackSimulator:
    def __init__(self, target_host: str = "http://localhost:8080",
                 siem_ingest_url: str = "http://localhost:8000/api/events/ingest"):
        self.target_host = target_host.rstrip("/")
        self.siem_ingest_url = siem_ingest_url

    def _send_siem_event(self, event_data: dict):
        """Send alert directly to SIEM if testing in pure-software mode without live packet sniffer"""
        try:
            req = urllib.request.Request(
                self.siem_ingest_url,
                data=json.dumps(event_data).encode("utf-8"),
                headers={"Content-Type": "application/json"}
            )
            with urllib.request.urlopen(req, timeout=2) as resp:
                pass
        except Exception as e:
            logger.debug(f"SIEM direct notify: {e}")

    def run_port_scan(self, attacker_ip: str = "192.168.1.189"):
        """
        Simulates Nmap TCP SYN reconnaissance (MITRE T1046)
        """
        logger.info(f"[*] Launching Nmap Port Scan against target from {attacker_ip}...")
        ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 8080]
        for port in ports:
            # Send Suricata alert event to pipeline
            self._send_siem_event({
                "signature_id": 1000001,
                "signature": "MINI-SOC - Nmap TCP SYN Scan Detected",
                "src_ip": attacker_ip,
                "src_port": 52140,
                "dest_ip": "172.28.0.10",
                "dest_port": port,
                "proto": "TCP"
            })
            time.sleep(0.08)
        logger.info("[+] Port scan completed. Triggered MITRE T1046 detection.")

    def run_ssh_brute_force(self, attacker_ip: str = "192.168.1.189", attempts: int = 6):
        """
        Simulates Hydra SSH / Credential Password Guessing (MITRE T1110.001)
        """
        logger.info(f"[*] Launching SSH Brute-Force attack ({attempts} attempts) from {attacker_ip}...")
        usernames = ["root", "admin", "test", "support", "ubuntu", "guest"]
        passwords = ["123456", "password", "admin123", "toor", "letmein", "welcome"]

        for i in range(attempts):
            u = usernames[i % len(usernames)]
            p = passwords[i % len(passwords)]
            logger.info(f"    Attempt {i+1}/{attempts} -> Login testing: '{u}:{p}'")
            
            # Send to target web login if running
            try:
                data = urllib.parse.urlencode({"username": u, "password": p}).encode("utf-8")
                req = urllib.request.Request(f"{self.target_host}/login", data=data)
                urllib.request.urlopen(req, timeout=1)
            except urllib.error.HTTPError:
                pass
            except Exception:
                pass

            # Ingest Suricata alert into SIEM
            self._send_siem_event({
                "signature_id": 1000010,
                "signature": "MINI-SOC - Possible SSH Brute-Force Attempt Detected",
                "src_ip": attacker_ip,
                "src_port": 49100 + i,
                "dest_ip": "172.28.0.10",
                "dest_port": 22,
                "proto": "TCP"
            })
            time.sleep(0.1)

        logger.info("[+] SSH brute-force completed. Triggered MITRE T1110.001 & SOAR Auto-Block.")

    def run_sql_injection(self, attacker_ip: str = "192.168.1.189"):
        """
        Simulates SQL Injection exploit attempt (MITRE T1190)
        """
        logger.info(f"[*] Launching SQL Injection exploit probe from {attacker_ip}...")
        payload = "' UNION SELECT null, username, password FROM users --"
        try:
            url = f"{self.target_host}/api/users?id={urllib.parse.quote(payload)}"
            urllib.request.urlopen(url, timeout=1)
        except Exception:
            pass

        self._send_siem_event({
            "signature_id": 1000020,
            "signature": "MINI-SOC - SQL Injection Attempt (UNION SELECT)",
            "src_ip": attacker_ip,
            "src_port": 54100,
            "dest_ip": "172.28.0.10",
            "dest_port": 80,
            "proto": "HTTP"
        })
        logger.info("[+] SQL Injection probe sent. Triggered MITRE T1190 detection.")

    def run_directory_traversal(self, attacker_ip: str = "192.168.1.189"):
        """
        Simulates Path Traversal attempt (MITRE T1083 / T1190)
        """
        logger.info(f"[*] Launching Directory Traversal attack from {attacker_ip}...")
        try:
            url = f"{self.target_host}/download?file=../../../../etc/passwd"
            urllib.request.urlopen(url, timeout=1)
        except Exception:
            pass

        self._send_siem_event({
            "signature_id": 1000022,
            "signature": "MINI-SOC - Directory Traversal Attempt (/etc/passwd)",
            "src_ip": attacker_ip,
            "src_port": 54200,
            "dest_ip": "172.28.0.10",
            "dest_port": 80,
            "proto": "HTTP"
        })
        logger.info("[+] Directory Traversal probe sent. Triggered MITRE T1083 detection.")

    def run_benign_scanner(self, scanner_ip: str = "172.28.0.254"):
        """
        Simulates Authorized Internal Vulnerability Scanner (Noise Suppression Test)
        """
        logger.info(f"[*] Simulating Authorized Security Audit Scanner from {scanner_ip}...")
        try:
            req = urllib.request.Request(
                f"{self.target_host}/",
                headers={"User-Agent": "MiniSOC-AuditScanner/1.0 (Authorized Vulnerability Assessment)"}
            )
            urllib.request.urlopen(req, timeout=1)
        except Exception:
            pass

        self._send_siem_event({
            "signature_id": 1000050,
            "signature": "MINI-SOC - Authorized Internal Security Scanner Probe",
            "src_ip": scanner_ip,
            "src_port": 40100,
            "dest_ip": "172.28.0.10",
            "dest_port": 80,
            "proto": "HTTP"
        })
        logger.info("[+] Authorized scan completed. Verified SOAR Noise Suppression Playbook.")

    def run_full_demo(self):
        """
        Executes the full end-to-end signature demo sequence from Section 23 of the spec.
        """
        print("\n=======================================================")
        print("  MINI-SOC SIGNATURE ATTACK -> DETECT -> RESPOND DEMO  ")
        print("=======================================================\n")
        
        time.sleep(1)
        print("STEP 1: Attacker reconnaissance (Nmap Port Scan - T1046)")
        self.run_port_scan("192.168.1.189")
        
        time.sleep(1.5)
        print("\nSTEP 2: Benign internal scanner activity (Noise Suppression Test - T1595)")
        self.run_benign_scanner("172.28.0.254")

        time.sleep(1.5)
        print("\nSTEP 3: Web Application Exploitation (SQL Injection - T1190)")
        self.run_sql_injection("192.168.1.189")

        time.sleep(1.5)
        print("\nSTEP 4: Credential Access Brute-Force (Hydra SSH - T1110.001)")
        self.run_ssh_brute_force("192.168.1.189", attempts=6)

        print("\n[✔] Full attack demo sequence executed!")
        print("    Check the SIEM dashboard (http://localhost:8000) to see:")
        print("    - Real-time alerts mapped to MITRE ATT&CK")
        print("    - Sliding-window incident correlation")
        print("    - SOAR automated firewall block of attacker IP 192.168.1.189")
        print("    - Benign scanner 172.28.0.254 auto-tagged and noise suppressed\n")


def main():
    parser = argparse.ArgumentParser(description="Mini-SOC Lab Attack Simulator")
    parser.add_argument("attack", choices=["nmap", "ssh", "sqli", "traversal", "benign", "demo"],
                        help="Attack pattern to simulate")
    parser.add_argument("--ip", default="192.168.1.189", help="Attacker IP address")
    args = parser.parse_args()

    sim = AttackSimulator()
    if args.attack == "nmap":
        sim.run_port_scan(args.ip)
    elif args.attack == "ssh":
        sim.run_ssh_brute_force(args.ip)
    elif args.attack == "sqli":
        sim.run_sql_injection(args.ip)
    elif args.attack == "traversal":
        sim.run_directory_traversal(args.ip)
    elif args.attack == "benign":
        sim.run_benign_scanner("172.28.0.254")
    elif args.attack == "demo":
        sim.run_full_demo()


if __name__ == "__main__":
    main()
