#!/usr/bin/env python3
"""Attack 3: Data Exfiltration - Database dump and DNS tunneling"""
import requests, time, sys

BACKEND_URL = "https://jair-falconnoid-unmechanically.ngrok-free.dev"

resp = requests.post(f"{BACKEND_URL}/api/auth/login", json={"username": "admin", "password": "sentinel-admin-2026"})
token = resp.json().get("token") or resp.json().get("access_token")
headers = {"Authorization": f"Bearer {token}"}

stages = [
    {"pod_name": "ehr", "syscall_name": "sys_read", "binary": "/usr/bin/mysqldump", "target": "/data/patient_records.sql", "params": {"stage": "db_dump", "size_mb": 250}},
    {"pod_name": "ehr", "syscall_name": "sys_sendto", "binary": "/usr/bin/curl", "target": "http://exfil.attacker.net/upload", "port": 443, "params": {"stage": "https_exfil"}},
    {"pod_name": "ehr", "syscall_name": "sys_sendto", "binary": "/usr/bin/dig", "target": "base64data.dns-exfil.attacker.net", "port": 53, "params": {"stage": "dns_tunneling"}}
]

for s in stages:
    requests.post(f"{BACKEND_URL}/api/telemetry/ingest", headers=headers, json={**s, "namespace": "medical", "source": "lab_test"})
    time.sleep(2)
