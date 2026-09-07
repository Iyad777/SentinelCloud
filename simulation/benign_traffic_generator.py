"""
SentinelCloud-Advanced: Benign Traffic Generator
==================================================
Generates realistic benign medical traffic to train the HMM
and establish a baseline for the Online Isolation Forest.

Run this for at least 1 hour before starting attack simulations
to allow the ML models to learn normal patterns.
"""

import os
import sys
import json
import time
import random
import logging
import argparse
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BENIGN] %(message)s",
)
logger = logging.getLogger("benign-traffic")

# Service endpoints (update for your environment)
SERVICES = {
    "vitals": os.environ.get("VITALS_URL", "http://vitals.medical.svc.cluster.local:5000"),
    "drug-dispenser": os.environ.get("DRUG_DISPENSER_URL", "http://drug-dispenser.medical.svc.cluster.local:5001"),
    "ehr": os.environ.get("EHR_URL", "http://ehr.medical.svc.cluster.local:5002"),
    "billing": os.environ.get("BILLING_URL", "http://billing.medical.svc.cluster.local:5003"),
}

DRUGS = ["aspirin", "morphine", "insulin", "amoxicillin", "metformin"]
DIAGNOSES = ["hypertension", "diabetes", "cardiac arrest", "pneumonia", "fracture"]
PATIENT_IDS = [f"P{i:04d}" for i in range(1, 51)]


def send_vitals():
    """Send a heartbeat to the vitals service."""
    patient = random.choice(PATIENT_IDS)
    data = {
        "patient_id": patient,
        "heart_rate": random.randint(60, 100),
        "bp_systolic": random.randint(110, 140),
        "bp_diastolic": random.randint(60, 90),
        "spo2": round(random.uniform(94, 100), 1),
    }
    try:
        resp = requests.post(f"{SERVICES['vitals']}/beat", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def check_vitals_health():
    """Check vitals service health."""
    try:
        resp = requests.get(f"{SERVICES['vitals']}/health", timeout=5)
        return resp.status_code
    except Exception:
        return 0


def dispense_drug():
    """Dispense a drug via the drug-dispenser service."""
    data = {
        "patient_id": random.choice(PATIENT_IDS),
        "drug_name": random.choice(DRUGS),
        "quantity": random.randint(1, 5),
        "prescriber_id": f"DR{random.randint(100, 999)}",
    }
    try:
        resp = requests.post(f"{SERVICES['drug-dispenser']}/dispense", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def create_ehr_record():
    """Create an EHR record."""
    patient = random.choice(PATIENT_IDS)
    data = {
        "patient_id": patient,
        "name": f"Patient {patient}",
        "diagnosis": random.choice(DIAGNOSES),
        "medications": random.sample(DRUGS, k=random.randint(1, 3)),
        "notes": f"Routine checkup at {datetime.utcnow().isoformat()}",
    }
    try:
        resp = requests.post(f"{SERVICES['ehr']}/record", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def get_ehr_record():
    """Retrieve an EHR record."""
    patient = random.choice(PATIENT_IDS)
    try:
        resp = requests.get(f"{SERVICES['ehr']}/record", params={"patient_id": patient}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def get_invoice():
    """Generate/retrieve an invoice."""
    patient = random.choice(PATIENT_IDS)
    try:
        resp = requests.get(f"{SERVICES['billing']}/invoice", params={"patient_id": patient}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def run_traffic(duration_minutes: int = 60, rate: float = 10.0):
    """Generate benign traffic at the specified rate (requests/second)."""
    logger.info("Starting benign traffic generation for %d minutes at %.1f req/s", duration_minutes, rate)

    actions = [
        (send_vitals, 3),       # weight 3 – most common
        (check_vitals_health, 2),
        (dispense_drug, 2),
        (create_ehr_record, 2),
        (get_ehr_record, 2),
        (get_invoice, 1),
    ]

    weighted_actions = []
    for action, weight in actions:
        weighted_actions.extend([action] * weight)

    end_time = time.time() + (duration_minutes * 60)
    interval = 1.0 / rate
    total_requests = 0
    errors = 0

    with ThreadPoolExecutor(max_workers=8) as executor:
        while time.time() < end_time:
            action = random.choice(weighted_actions)
            future = executor.submit(action)

            try:
                status = future.result(timeout=10)
                total_requests += 1
                if status == 0 or status >= 500:
                    errors += 1
            except Exception:
                errors += 1

            if total_requests % 100 == 0:
                elapsed = (duration_minutes * 60) - (end_time - time.time())
                logger.info(
                    "Progress: %d requests sent, %d errors, %.0f seconds elapsed",
                    total_requests, errors, elapsed,
                )

            time.sleep(interval + random.uniform(-0.01, 0.01))

    logger.info("Traffic generation complete: %d requests, %d errors", total_requests, errors)
    return total_requests, errors


def main():
    parser = argparse.ArgumentParser(description="Benign Traffic Generator")
    parser.add_argument("--duration", type=int, default=60, help="Duration in minutes (default: 60)")
    parser.add_argument("--rate", type=float, default=10.0, help="Requests per second (default: 10)")
    args = parser.parse_args()

    run_traffic(args.duration, args.rate)


if __name__ == "__main__":
    main()
