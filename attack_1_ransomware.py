#!/usr/bin/env python3
"""Attack 1: Ransomware - File encryption campaign"""
import requests, time, sys

BACKEND_URL = "https://jair-falconnoid-unmechanically.ngrok-free.dev"

resp = requests.post(f"{BACKEND_URL}/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
token = resp.json().get("token") or resp.json().get("access_token")
headers = {"Authorization": f"Bearer {token}"}

stages = [
    {"pod_name": "ehr", "syscall_name": "sys_execve", "binary": "/bin/bash", "target": "/tmp/malware.sh", "params": {"stage": "shell_spawn"}},
    {"pod_name": "ehr", "syscall_name": "sys_rename", "binary": "/usr/bin/openssl", "target": "/data/patients.db.encrypted", "params": {"stage": "encryption"}},
    {"pod_name": "ehr", "syscall_name": "sys_connect", "binary": "/usr/bin/nc", "target": "attacker-c2.onion:8443", "port": 8443, "params": {"stage": "c2_callback"}},
    {"pod_name": "ehr", "syscall_name": "sys_write", "binary": "/bin/bash", "target": "/data/RANSOM_NOTE.txt", "params": {"stage": "ransom_note"}}
]

for s in stages:
    requests.post(f"{BACKEND_URL}/api/telemetry/ingest", headers=headers, json={**s, "namespace": "medical", "source": "lab_test"})
    time.sleep(2)
