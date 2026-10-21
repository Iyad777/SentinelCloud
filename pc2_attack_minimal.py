#!/usr/bin/env python3
"""
SentinelCloud PC2 Attack Client (Minimal)
==========================================
Silent multi-stage ransomware simulation.
"""

import requests
import time
import sys

BACKEND_URL = "https://jair-falconnoid-unmechanically.ngrok-free.dev"
USERNAME = "admin"
PASSWORD = "sentinel-admin-2026"

ATTACK_STAGES = [
    {"stage": "recon", "target": "http://ehr:5002/api/patients"},
    {"stage": "lateral", "target": "http://ehr:5002/api/mri_scans"},
    {"stage": "exfil", "target": "http://billing:5003/api/invoices"},
    {"stage": "ransom", "target": "http://drug-dispenser:5001/api/encrypt_all"},
]

try:
    # Authenticate
    resp = requests.post(f"{BACKEND_URL}/api/auth/login", 
                        json={"username": USERNAME, "password": PASSWORD},
                        timeout=10)
    if resp.status_code != 200:
        sys.exit(1)
    
    token = resp.json().get("access_token") or resp.json().get("token")
    if not token:
        sys.exit(1)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Execute attack
    for stage in ATTACK_STAGES:
        requests.post(
            f"{BACKEND_URL}/api/telemetry/ingest",
            headers=headers,
            json={
                "pod_name": "ehr",
                "namespace": "medical",
                "syscall_name": "sys_execve",
                "binary": "/bin/bash",
                "target": stage["target"],
                "source": "lab_test",
                "params": {"stage": stage["stage"]},
            },
            timeout=15
        )
        time.sleep(2)
    
    # Success - silent exit
    sys.exit(0)

except Exception:
    sys.exit(1)
