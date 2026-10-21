#!/usr/bin/env python3
"""
Extract Results & Metrics from SentinelCloud
============================================
Generates thesis-ready metrics, statistics, and CSV data for graphs.
"""

import requests
import json
import csv
from datetime import datetime
from statistics import mean, stdev
import sys

BACKEND_URL = "http://localhost:5050"
USERNAME = "admin"
PASSWORD = "sentinel-admin-2026"

def authenticate():
    """Get JWT token."""
    resp = requests.post(f"{BACKEND_URL}/api/auth/login", 
                        json={"username": USERNAME, "password": PASSWORD})
    if resp.status_code != 200:
        print("❌ Authentication failed")
        sys.exit(1)
    data = resp.json()
    return data.get("token") or data.get("access_token")

def get_metrics(token):
    """Fetch system metrics."""
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(f"{BACKEND_URL}/api/metrics", headers=headers).json()

def get_incidents(token):
    """Fetch all incidents."""
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(f"{BACKEND_URL}/api/incidents?limit=1000", headers=headers).json()

def get_detections(token):
    """Fetch detection results."""
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(f"{BACKEND_URL}/api/detection/recent?limit=5000", headers=headers).json()

def get_telemetry(token):
    """Fetch telemetry events."""
    headers = {"Authorization": f"Bearer {token}"}
    return requests.get(f"{BACKEND_URL}/api/telemetry/recent?limit=5000", headers=headers).json()

def main():
    print("=" * 70)
    print("  SentinelCloud Results Extraction")
    print("=" * 70)
    print()
    
    # Authenticate
    print("🔐 Authenticating...")
    token = authenticate()
    print("✅ Authenticated\n")
    
    # Fetch data
    print("📊 Fetching metrics...")
    metrics = get_metrics(token)
    incidents_data = get_incidents(token)
    detections_data = get_detections(token)
    telemetry_data = get_telemetry(token)
    
    incidents = incidents_data.get("incidents", [])
    detections = detections_data.get("detections", [])
    events = telemetry_data.get("events", [])
    
    print(f"✅ Fetched {len(incidents)} incidents, {len(detections)} detections, {len(events)} events\n")
    
    # ==================== RESULTS ====================
    
    print("=" * 70)
    print("  KEY RESULTS")
    print("=" * 70)
    print()
    
    # 1. Incident Statistics
    resolved = [i for i in incidents if i.get("resolved")]
    mttr_values = [i["mttr_ms"] for i in incidents if i.get("mttr_ms")]
    
    print("📋 INCIDENT STATISTICS")
    print(f"   Total Incidents: {len(incidents)}")
    print(f"   Resolved: {len(resolved)} ({len(resolved)/len(incidents)*100:.1f}%)")
    print(f"   Active/Pending: {len(incidents) - len(resolved)}")
    print()
    
    if mttr_values:
        print("⏱️  MEAN TIME TO REMEDIATE (MTTR)")
        print(f"   Average: {mean(mttr_values):.2f} ms")
        print(f"   Median: {sorted(mttr_values)[len(mttr_values)//2]:.2f} ms")
        print(f"   Min: {min(mttr_values):.2f} ms")
        print(f"   Max: {max(mttr_values):.2f} ms")
        if len(mttr_values) > 1:
            print(f"   Std Dev: {stdev(mttr_values):.2f} ms")
        print()
    
    # 2. Severity Breakdown
    severity_counts = {}
    for i in incidents:
        sev = i.get("severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print("🚨 SEVERITY BREAKDOWN")
    for sev, count in sorted(severity_counts.items()):
        pct = count / len(incidents) * 100
        print(f"   {sev}: {count} ({pct:.1f}%)")
    print()
    
    # 3. Detection Methods
    method_counts = {}
    for d in detections:
        method = d.get("detection_method", "NONE")
        method_counts[method] = method_counts.get(method, 0) + 1
    
    print("🔍 DETECTION METHODS")
    total_detections = sum(method_counts.values())
    for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
        pct = count / total_detections * 100 if total_detections > 0 else 0
        print(f"   {method}: {count} ({pct:.1f}%)")
    print()
    
    # 4. System Metrics
    print("📈 SYSTEM METRICS")
    print(f"   Total Events Processed: {metrics.get('total_events', 0)}")
    print(f"   Total Detections: {metrics.get('total_detections', 0)}")
    print(f"   Detection Rate: {metrics.get('detection_rate', 0):.2%}")
    print(f"   Avg Anomaly Score: {metrics.get('avg_anomaly_score', 0):.4f}")
    print()
    
    # ==================== EXPORT CSV ====================
    
    print("=" * 70)
    print("  EXPORTING DATA FOR GRAPHS")
    print("=" * 70)
    print()
    
    # CSV 1: Incidents Over Time
    with open('incidents_timeline.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Incident ID', 'Created At', 'Severity', 'MTTR (ms)', 'Resolved', 'Phase'])
        for i in incidents:
            writer.writerow([
                i.get('incident_id'),
                i.get('created_at'),
                i.get('severity'),
                i.get('mttr_ms', 0),
                i.get('resolved', False),
                i.get('phase')
            ])
    print("✅ incidents_timeline.csv")
    
    # CSV 2: MTTR Distribution
    with open('mttr_distribution.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Incident ID', 'MTTR (ms)'])
        for i in incidents:
            if i.get('mttr_ms'):
                writer.writerow([i['incident_id'], i['mttr_ms']])
    print("✅ mttr_distribution.csv")
    
    # CSV 3: Detection Methods
    with open('detection_methods.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Method', 'Count', 'Percentage'])
        for method, count in method_counts.items():
            pct = count / total_detections * 100 if total_detections > 0 else 0
            writer.writerow([method, count, pct])
    print("✅ detection_methods.csv")
    
    # CSV 4: Severity Distribution
    with open('severity_distribution.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Severity', 'Count', 'Percentage'])
        for sev, count in severity_counts.items():
            pct = count / len(incidents) * 100
            writer.writerow([sev, count, pct])
    print("✅ severity_distribution.csv")
    
    # CSV 5: Anomaly Scores
    with open('anomaly_scores.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Event ID', 'Timestamp', 'Anomaly Score', 'Is Alert'])
        for e in events:
            if e.get('anomaly_score') is not None:
                writer.writerow([
                    e.get('event_id'),
                    e.get('timestamp'),
                    e.get('anomaly_score'),
                    e.get('is_alert', False)
                ])
    print("✅ anomaly_scores.csv")
    
    print()
    print("=" * 70)
    print("  ✅ EXTRACTION COMPLETE")
    print("=" * 70)
    print()
    print("📁 Files created:")
    print("   - incidents_timeline.csv")
    print("   - mttr_distribution.csv")
    print("   - detection_methods.csv")
    print("   - severity_distribution.csv")
    print("   - anomaly_scores.csv")
    print()
    print("💡 Import these CSVs into Excel, Python (matplotlib/seaborn), or R for graphs")

if __name__ == "__main__":
    main()
