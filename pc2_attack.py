#!/usr/bin/env python3
"""
SentinelCloud PC2 Attack Client
================================
Runs a 4-stage ransomware attack against SentinelCloud backend via ngrok tunnel.

Usage:
    1. Replace BACKEND_URL with your ngrok URL
    2. Run: python pc2_attack.py
    3. Watch incidents appear on Ubuntu dashboard in real-time

Requirements: pip install requests
"""

import requests
import time
import sys
from datetime import datetime

# ============================================================================
# CONFIGURATION - Replace with your ngrok URL
# ============================================================================
BACKEND_URL = "https://jair-falconnoid-unmechanically.ngrok-free.dev"
USERNAME = "admin"
PASSWORD = "sentinel-admin-2026"

# Attack stages
ATTACK_STAGES = [
    {
        "stage": "recon",
        "target": "http://ehr:5002/api/patients",
        "description": "📊 RECON: Scanning patient database",
    },
    {
        "stage": "lateral",
        "target": "http://ehr:5002/api/mri_scans",
        "description": "🔀 LATERAL: Accessing MRI imaging systems",
    },
    {
        "stage": "exfil",
        "target": "http://billing:5003/api/invoices",
        "description": "💸 EXFIL: Extracting financial records",
    },
    {
        "stage": "ransom",
        "target": "http://drug-dispenser:5001/api/encrypt_all",
        "description": "🔒 RANSOM: Encrypting drug dispenser database",
    },
]


def print_banner():
    """Print attack banner."""
    print("=" * 70)
    print("  SentinelCloud PC2 Attack Client")
    print("  Multi-stage Ransomware Simulation")
    print("=" * 70)
    print()


def check_backend_health(base_url, headers):
    """Check if backend is reachable."""
    try:
        resp = requests.get(f"{base_url}/api/health", headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            print(f"✅ Backend Health: {data.get('status', 'unknown')}")
            return True
    except Exception as e:
        print(f"❌ Backend unreachable: {e}")
        return False
    return False


def authenticate(base_url):
    """Authenticate and get JWT token."""
    print(f"🔐 Authenticating as '{USERNAME}'...")
    try:
        resp = requests.post(
            f"{base_url}/api/auth/login",
            json={"username": USERNAME, "password": PASSWORD},
            timeout=10,
        )
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            print(f"✅ Authenticated successfully")
            return token
        else:
            print(f"❌ Authentication failed: {resp.status_code} {resp.text}")
            return None
    except Exception as e:
        print(f"❌ Authentication error: {e}")
        return None


def execute_attack_stage(base_url, headers, stage_num, stage_data):
    """Execute a single attack stage."""
    print(f"\n[Stage {stage_num}/4] {stage_data['description']}")
    print(f"  Target: {stage_data['target']}")
    
    try:
        resp = requests.post(
            f"{base_url}/api/telemetry/inject",
            headers=headers,
            json={
                "stage": stage_data["stage"],
                "target": stage_data["target"],
            },
            timeout=15,
        )
        
        if resp.status_code == 200:
            result = resp.json()
            score = result.get("anomaly_score", 0)
            method = result.get("detection_method", "NONE")
            print(f"  ✅ Status: {resp.status_code}")
            print(f"  📊 Anomaly Score: {score:.4f}")
            print(f"  🔍 Detection: {method}")
            return True
        else:
            print(f"  ❌ Failed: {resp.status_code} {resp.text[:100]}")
            return False
            
    except Exception as e:
        print(f"  ❌ Error: {e}")
        return False


def get_incident_status(base_url, headers):
    """Check if an incident was created."""
    try:
        resp = requests.get(f"{base_url}/api/incidents", headers=headers, timeout=10)
        if resp.status_code == 200:
            incidents = resp.json().get("incidents", [])
            if incidents:
                latest = incidents[0]
                print(f"\n🚨 INCIDENT CREATED: {latest['incident_id']}")
                print(f"   Severity: {latest.get('severity', 'unknown')}")
                print(f"   Phase: {latest.get('phase', 'unknown')}")
                print(f"   MTTR: {latest.get('mttr_ms', 0):.2f}ms")
                return True
    except Exception as e:
        print(f"⚠️  Could not fetch incident status: {e}")
    return False


def main():
    """Main attack execution."""
    print_banner()
    
    # Validate configuration
    if "YOUR-NGROK-URL" in BACKEND_URL:
        print("❌ ERROR: Please update BACKEND_URL with your ngrok URL!")
        print("   Get it from: http://127.0.0.1:4040 (on Ubuntu VM)")
        sys.exit(1)
    
    print(f"🎯 Target: {BACKEND_URL}")
    print(f"📅 Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # Authenticate
    token = authenticate(BACKEND_URL)
    if not token:
        print("\n❌ Attack aborted: Authentication failed")
        sys.exit(1)
    
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    
    # Check backend health
    print()
    if not check_backend_health(BACKEND_URL, headers):
        print("\n⚠️  Backend health check failed, but continuing anyway...")
    
    print("\n" + "=" * 70)
    print("  Starting Multi-Stage Attack Sequence")
    print("=" * 70)
    
    # Execute attack stages
    success_count = 0
    for i, stage in enumerate(ATTACK_STAGES, 1):
        if execute_attack_stage(BACKEND_URL, headers, i, stage):
            success_count += 1
        time.sleep(2)  # Delay between stages
    
    # Summary
    print("\n" + "=" * 70)
    print("  Attack Sequence Complete")
    print("=" * 70)
    print(f"✅ Stages Executed: {success_count}/{len(ATTACK_STAGES)}")
    
    # Check for incident creation
    print("\n🔍 Checking for autonomous incident response...")
    time.sleep(3)  # Give backend time to correlate and create incident
    get_incident_status(BACKEND_URL, headers)
    
    print("\n✅ Attack simulation complete!")
    print("   Check Ubuntu dashboard for incident details and remediation status.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
        sys.exit(0)
