"""
SentinelCloud-Advanced: Benign Traffic Generator
==================================================
Sends REAL HTTP requests to the medical service endpoints (vitals:5000,
drug-dispenser:5001, ehr:5002, billing:5003). Each request produces a real
Flask JSON access-log line, which LogTailIngester tails as genuine HTTP_LOG
telemetry for the detection pipeline.

Usage:
  python simulation/benign_traffic_generator.py --duration 60 --rate 10
  python simulation/benign_traffic_generator.py --mode attack --duration 2

Modes:
  benign (default) — clinician reads, record creates, health checks, billing
  attack           — adds bulk reads, DELETE probes, oversized payloads and
                     repeated 4xx to exercise rule/ML response on real traffic
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
    "vitals": os.environ.get("VITALS_URL", "http://localhost:5000"),
    "drug-dispenser": os.environ.get("DRUG_DISPENSER_URL", "http://localhost:5001"),
    "ehr": os.environ.get("EHR_URL", "http://localhost:5002"),
    "billing": os.environ.get("BILLING_URL", "http://localhost:5003"),
}

DRUGS = ["aspirin", "morphine", "insulin", "amoxicillin", "metformin"]
DIAGNOSES = ["hypertension", "diabetes", "cardiac arrest", "pneumonia", "fracture"]

PATIENTS: list[dict] = []


def _load_patients() -> list[dict]:
    """Load synthetic patients; fall back to generated IDs if file missing."""
    global PATIENTS
    if PATIENTS:
        return PATIENTS
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (os.path.join(here, "..", "data", "synthetic_patients.json"),
                      os.path.join(os.getcwd(), "data", "synthetic_patients.json")):
        try:
            with open(candidate) as fh:
                PATIENTS = json.load(fh).get("patients", [])
                break
        except (OSError, ValueError):
            continue
    if not PATIENTS:
        PATIENTS = [{"patient_id": f"P{i:04d}", "diagnosis": random.choice(DIAGNOSES),
                     "medications": random.sample(DRUGS, k=2)} for i in range(1, 51)]
    return PATIENTS


def _patient() -> dict:
    return random.choice(_load_patients())


def send_vitals():
    """Send a heartbeat to the vitals service (POST /beat)."""
    p = _patient()
    data = {
        "patient_id": p["patient_id"],
        "heart_rate": p.get("heart_rate", random.randint(60, 100)),
        "bp_systolic": p.get("bp_systolic", random.randint(110, 140)),
        "bp_diastolic": p.get("bp_diastolic", random.randint(60, 90)),
        "spo2": p.get("spo2", round(random.uniform(94, 100), 1)),
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
    """Dispense a drug via the drug-dispenser service (POST /dispense)."""
    p = _patient()
    data = {
        "patient_id": p["patient_id"],
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
    """Create an EHR record (POST /record)."""
    p = _patient()
    data = {
        "patient_id": p["patient_id"],
        "name": p.get("name", f"Patient {p['patient_id']}"),
        "diagnosis": p.get("diagnosis", random.choice(DIAGNOSES)),
        "medications": p.get("medications", random.sample(DRUGS, k=random.randint(1, 3))),
        "notes": f"Routine checkup at {datetime.utcnow().isoformat()}",
    }
    try:
        resp = requests.post(f"{SERVICES['ehr']}/record", json=data, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def get_ehr_record():
    """Retrieve an EHR record (GET /record?patient_id=...)."""
    p = _patient()
    try:
        resp = requests.get(f"{SERVICES['ehr']}/record", params={"patient_id": p["patient_id"]}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def get_invoice():
    """Generate/retrieve an invoice (GET /invoice?patient_id=...)."""
    p = _patient()
    try:
        resp = requests.get(f"{SERVICES['billing']}/invoice", params={"patient_id": p["patient_id"]}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


# ── Attack-pattern requests (real anomalous HTTP, for --mode attack) ──

def bulk_read_records():
    """Bulk GET /records sweep (data-gathering pattern)."""
    try:
        resp = requests.get(f"{SERVICES['ehr']}/records", timeout=5)
        return resp.status_code
    except Exception:
        return 0


def delete_probe():
    """DELETE probe against the EHR service (405/404 expected; unusual method)."""
    p = _patient()
    try:
        resp = requests.delete(f"{SERVICES['ehr']}/record", params={"patient_id": p["patient_id"]}, timeout=5)
        return resp.status_code
    except Exception:
        return 0


def oversized_record():
    """POST an oversized EHR payload (exfil-shaped write)."""
    p = _patient()
    data = {
        "patient_id": p["patient_id"],
        "name": "bulk-export",
        "diagnosis": "export",
        "medications": [],
        "notes": "X" * 60000,
    }
    try:
        resp = requests.post(f"{SERVICES['ehr']}/record", json=data, timeout=10)
        return resp.status_code
    except Exception:
        return 0


def missing_patient_probe():
    """GET /record without patient_id (repeated 400s = bruteforce-shaped)."""
    try:
        resp = requests.get(f"{SERVICES['ehr']}/record", timeout=5)
        return resp.status_code
    except Exception:
        return 0


def run_traffic(duration_minutes: int = 60, rate: float = 10.0, mode: str = "benign"):
    """Generate traffic at the specified rate (requests/second).

    benign: clinician reads every 3-5s cadence, occasional creates,
            health checks, billing queries — real HTTP to medical services.
    attack: benign mix plus bulk reads, DELETE probes, oversized payloads
            and repeated 4xx to exercise detection on real anomalous HTTP.
    """
    logger.info("Starting %s traffic generation for %d minutes at %.1f req/s",
                mode, duration_minutes, rate)

    actions = [
        (get_ehr_record, 4),       # clinician reads — most common
        (send_vitals, 3),
        (check_vitals_health, 2),  # health checks
        (get_invoice, 2),          # billing queries
        (create_ehr_record, 1),    # occasional creates
        (dispense_drug, 1),
    ]
    if mode == "attack":
        actions += [
            (bulk_read_records, 2),
            (missing_patient_probe, 2),
            (delete_probe, 1),
            (oversized_record, 1),
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
    parser = argparse.ArgumentParser(description="Benign Traffic Generator (real HTTP to medical services)")
    parser.add_argument("--duration", type=int, default=60, help="Duration in minutes (default: 60)")
    parser.add_argument("--rate", type=float, default=10.0, help="Requests per second (default: 10)")
    parser.add_argument("--mode", choices=["benign", "attack"], default="benign",
                        help="benign: normal clinician traffic; attack: adds anomalous HTTP patterns")
    args = parser.parse_args()

    run_traffic(args.duration, args.rate, mode=args.mode)


if __name__ == "__main__":
    main()
