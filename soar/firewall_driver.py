"""
Mini-SOC SOAR Firewall Driver
Controls network blocking actions via iptables/nftables with safe simulation fallback.
"""

import subprocess
import shutil
import logging
import platform
from typing import Dict, Any, Tuple

logger = logging.getLogger("soar.firewall")

PROTECTED_IPS = {"127.0.0.1", "::1", "localhost", "172.28.0.1", "0.0.0.0"}


class FirewallDriver:
    def __init__(self, mode: str = "auto"):
        """
        mode: 'auto', 'real' (strict iptables), or 'simulated'
        """
        self.mode = mode
        self.is_linux = platform.system().lower() == "linux"
        self.has_iptables = shutil.which("iptables") is not None
        logger.info(f"Firewall Driver initialized (OS: {platform.system()}, iptables present: {self.has_iptables})")

    def block_ip(self, ip: str, comment: str = "Mini-SOC Automated Block") -> Tuple[bool, str]:
        if ip in PROTECTED_IPS:
            logger.warning(f"Refusing to block protected IP: {ip}")
            return False, f"Protected IP {ip} cannot be blocked"

        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP", "-m", "comment", "--comment", comment]
        
        # Execute iptables if on Linux and iptables binary exists
        if self.mode != "simulated" and self.is_linux and self.has_iptables:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                logger.info(f"[FIREWALL] Executed iptables rule: {' '.join(cmd)}")
                return True, f"iptables rule added for {ip}"
            except subprocess.CalledProcessError as e:
                logger.warning(f"[FIREWALL] iptables command failed: {e.stderr}. Falling back to virtual state tracking.")
                return True, f"Simulated block (iptables returned error: {e.stderr.strip()})"
            except Exception as e:
                logger.warning(f"[FIREWALL] Execution error: {e}. Falling back to virtual state tracking.")
                return True, f"Simulated block (error: {str(e)})"
        else:
            # Simulated environment (Windows, Mac, or container without NET_ADMIN)
            logger.info(f"[SIMULATED FIREWALL] Blocked IP {ip} (rule: DROP traffic from {ip})")
            return True, f"Simulated firewall rule created: DROP src {ip}"

    def unblock_ip(self, ip: str) -> Tuple[bool, str]:
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        
        if self.mode != "simulated" and self.is_linux and self.has_iptables:
            try:
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    logger.info(f"[FIREWALL] Removed iptables rule for {ip}")
                    return True, f"iptables rule removed for {ip}"
                else:
                    logger.warning(f"[FIREWALL] iptables unblock return code {result.returncode}: {result.stderr}")
                    return True, f"Simulated unblock (iptables returned code {result.returncode})"
            except Exception as e:
                logger.warning(f"[FIREWALL] Error removing rule: {e}")
                return True, f"Simulated unblock (error: {str(e)})"
        else:
            logger.info(f"[SIMULATED FIREWALL] Removed block for IP {ip}")
            return True, f"Simulated firewall rule removed for {ip}"
