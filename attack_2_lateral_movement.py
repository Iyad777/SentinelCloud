#!/usr/bin/env python3
"""Attack 2: Lateral Movement - SSH pivoting across services"""
import requests, time, sys

BACKEND_URL = "https://jair-falconnoid-unmechanically.ngrok-free.dev"

resp = requests.post(f"{BACKEND_URL}/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
token = resp.json().get("token") or resp.json().get("access_token")
headers = {"Authorization": f"Bearer {token}"}

stages = [
    {"pod_name": "ehr", "syscall_name": "sys_connect", "binary": "/usr/bin/ssh", "target": "billing:22", "port": 22, "params": {"stage": "ssh_pivot"}},
    {"pod_name": "billing", "syscall_name": "sys_execve", "binary": "/bin/bash", "target": "/tmp/pivot.sh", "params": {"stage": "post_exploitation"}},
    {"pod_name": "billing", "syscall_name": "sys_connect", "binary": "/usr/bin/smbclient", "target": "vitals:445", "port": 445, "params": {"stage": "smb_enum"}},
    {"pod_name": "vitals", "syscall_name": "sys_read", "binary": "/bin/cat", "target": "/etc/shadow", "params": {"stage": "credential_theft"}}
]

for s in stages:
    requests.post(f"{BACKEND_URL}/api/telemetry/ingest", headers=headers, json={**s, "namespace": "medical", "source": "lab_test"})
    time.sleep(2)
