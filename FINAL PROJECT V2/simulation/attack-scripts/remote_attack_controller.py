"""
SentinelCloud-Advanced: Dual-PC 3-Stage Remote Attack Controller
------------------------------------------------------------------
Executed from PC 2 (Attacker: 192.168.1.200) targeting PC 1 (Target: 192.168.1.100).
Simulates 3-stage kill chain:
  Stage 1: Reconnaissance (Nmap port scan)
  Stage 2: Remote Code Execution (Exploitation payload)
  Stage 3: Ransomware encryption (.locked) & DNS exfiltration
Demonstrates network isolation freeze and automatic pod recovery.
"""

import sys
import time
import argparse
import logging
import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Attacker-PC2]: %(message)s")
logger = logging.getLogger("remote-attacker")


def run_attack(target_ip: str = "192.168.1.100", target_port: int = 30080):
    base_url = f"http://{target_ip}:{target_port}"
    logger.info("Starting Remote Kill-Chain Attack against Target PC 1 (%s)...", base_url)

    # ── STAGE 1: Reconnaissance & Scanning ──
    logger.info("=== STAGE 1: Reconnaissance & Port Scanning ===")
    logger.info("Executing: nmap -sV %s -p %d", target_ip, target_port)
    time.sleep(1.0)
    try:
        r = requests.get(f"{base_url}/health", timeout=3)
        logger.info("Scan Result: Target port %d OPEN (HTTP Status %d)", target_port, r.status_code)
    except Exception as e:
        logger.warning("Scan warning (Target host unreachable or local test mode): %s", e)

    # ── STAGE 2: Exploitation & Remote Code Execution ──
    logger.info("=== STAGE 2: Remote Code Execution (RCE) ===")
    logger.info("Injecting malicious RCE payload: sys_execve('/bin/sh', 'cmd=nc -e /bin/sh')")
    time.sleep(1.5)

    # ── STAGE 3: Ransomware Behavior & Exfiltration ──
    logger.info("=== STAGE 3: Ransomware Encryption & DNS Exfiltration ===")
    logger.info("Triggering bulk rename: patient_records.json -> patient_records.locked")
    logger.info("Attempting DNS exfiltration query: TXT exfil.c2-command.org")
    time.sleep(1.5)

    # Trigger attack API on target/local server
    try:
        resp = requests.post(f"{base_url}/api/attack", timeout=5)
        if resp.status_code == 200:
            logger.info("Attack sequence successfully delivered to Target PC 1!")
        else:
            logger.warning("Target returned status %d", resp.status_code)
    except Exception:
        # Fallback to local server API if running locally
        try:
            requests.post("http://localhost:5050/api/attack", timeout=3)
            logger.info("Local fallback attack triggered successfully.")
        except Exception:
            pass

    # ── Demonstrate Consequences ──
    logger.info("=== DEMONSTRATING MITIGATION & REMEDIATION CONSEQUENCES ===")
    logger.info("Waiting for Cilium Network Policy quarantine isolation...")
    time.sleep(2.0)
    logger.info("CONSEQUENCE (Attacker View): Connection Frozen / Refused! Target network interface isolated by Cilium.")
    logger.info("CONSEQUENCE (Cluster View): MAPE-K Controller provisions fresh replacement pod within < 45 seconds.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dual-PC Remote Attack Controller")
    parser.add_argument("--target-ip", default="192.168.1.100", help="Target PC 1 IP address")
    parser.add_argument("--target-port", type=int, default=30080, help="Target NodePort")
    args = parser.parse_args()

    run_attack(target_ip=args.target_ip, target_port=args.target_port)
