"""
SentinelCloud Synthetic Baseline Generator
==========================================
Honest SYNTHETIC-labelled warm-up events for the online HalfSpaceTrees model
during cold-start. Real telemetry comes from LogTailIngester (tailed Flask
JSON access logs). Attack injection is via PC2 / testing/scenarios only.
"""

import time
import random
import threading
import logging
from typing import Optional

from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode, ServiceStatus

logger = logging.getLogger("sentinel.live_generator")

# Clinical normal event templates
CLINICAL_EVENTS = [
    # EHR Service
    {
        "pod_name": "ehr",
        "syscall_name": "sys_read",
        "binary": "/usr/local/bin/gunicorn",
        "target": "/data/patient_records.json",
        "port": 0,
        "payload_size": 0,
        "params": {"query": "SELECT patient_history FROM records WHERE patient_id='PT-7821'", "actor": "dr_evans@hospital.local"},
    },
    {
        "pod_name": "ehr",
        "syscall_name": "sys_openat",
        "binary": "/usr/local/bin/gunicorn",
        "target": "/data/lab_results_2026.json",
        "port": 0,
        "payload_size": 0,
        "params": {"query": "GET /api/v1/lab_results/cbc", "actor": "nurse_patel@hospital.local"},
    },
    {
        "pod_name": "ehr",
        "syscall_name": "sys_read",
        "binary": "/usr/local/bin/gunicorn",
        "target": "/data/prescriptions.json",
        "port": 0,
        "payload_size": 0,
        "params": {"query": "VERIFY prescription_auth FOR rx_id='RX-99214'", "actor": "pharm_davis@hospital.local"},
    },

    # Vitals Monitor
    {
        "pod_name": "vitals",
        "syscall_name": "sys_recvfrom",
        "binary": "/app/vitals_collector",
        "target": "icu-bedside:9002",
        "port": 9002,
        "payload_size": 0,
        "params": {"channel": "ecg_lead_ii", "sample_rate": 250, "metric": "heart_rate_bpm:74"},
    },
    {
        "pod_name": "vitals",
        "syscall_name": "sys_recvfrom",
        "binary": "/app/vitals_collector",
        "target": "icu-bedside:9002",
        "port": 9002,
        "payload_size": 0,
        "params": {"channel": "pulse_oximeter", "sample_rate": 100, "metric": "spo2_pct:98.5"},
    },
    {
        "pod_name": "vitals",
        "syscall_name": "sys_write",
        "binary": "/app/vitals_collector",
        "target": "/data/vitals_timeseries.dat",
        "port": 0,
        "payload_size": 0,
        "params": {"batch_size": 64, "compression": "zstd"},
    },

    # Smart Drug Dispenser
    {
        "pod_name": "drug-dispenser",
        "syscall_name": "sys_write",
        "binary": "/usr/bin/dispenser_srv",
        "target": "/dev/ttyUSB0",
        "port": 0,
        "payload_size": 0,
        "params": {"pump_id": "PUMP-03", "infusion_rate_ml_hr": 2.5, "medication": "Regular Insulin"},
    },
    {
        "pod_name": "drug-dispenser",
        "syscall_name": "sys_read",
        "binary": "/usr/bin/dispenser_srv",
        "target": "/data/drug_formulary.json",
        "port": 0,
        "payload_size": 0,
        "params": {"check": "max_dose_limit", "drug_code": "INS-REG-100"},
    },

    # Billing Ledger
    {
        "pod_name": "billing",
        "syscall_name": "sys_connect",
        "binary": "/usr/bin/billing_api",
        "target": "payment-gw:443",
        "port": 443,
        "payload_size": 0,
        "params": {"action": "claims_audit", "claim_id": "CLM-48201", "icd10": "E11.9"},
    },
    {
        "pod_name": "billing",
        "syscall_name": "sys_read",
        "binary": "/usr/bin/billing_api",
        "target": "/data/icd10_codes.db",
        "port": 0,
        "payload_size": 0,
        "params": {"lookup": "E11.9", "description": "Type 2 diabetes without complications"},
    },
]


class LiveTrafficGenerator:
    """
    Synthetic baseline warm-up generator.

    Honest role: emits SYNTHETIC-labelled baseline events during the HMM's
    cold-start period so the online HalfSpaceTrees model has an initial
    distribution. Real telemetry comes from LogTailIngester (tailed Flask
    JSON access logs). Manual attack injection is via PC2 / testing/scenarios.
    Auto-attacks were removed — this generator emits baseline only.
    """

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="LiveTrafficGenerator")
        self.thread.start()
        logger.info("Synthetic baseline generator started (SYNTHETIC-labelled warm-up only)")

    def stop(self):
        self.running = False
        logger.info("Synthetic baseline generator stopped")

    def _run_loop(self):
        # Initial warm-up delay
        time.sleep(3.0)

        while self.running:
            try:
                self._emit_normal_event()

                # Variable rate: sleep between 1.2s and 2.8s
                sleep_time = random.uniform(1.2, 2.8)
                time.sleep(sleep_time)

            except Exception as e:
                logger.error("Error in live telemetry generator loop: %s", e)
                time.sleep(2.0)

    def _emit_normal_event(self):
        """Emit a synthetic baseline warm-up event (clearly labelled SYNTHETIC)."""
        template = random.choice(CLINICAL_EVENTS)
        # Avoid emitting normal events to a pod currently undergoing quarantine/redeploy
        pod_status = self.pipeline.services.get(template["pod_name"])
        if pod_status and pod_status.status != ServiceStatus.HEALTHY:
            return

        event = TelemetryEvent(
            source=TelemetrySource.HTTP_INGESTION,
            data_mode=DataMode.SYNTHETIC,
            pod_name=template["pod_name"],
            namespace="medical",
            syscall_name=template["syscall_name"],
            binary=template["binary"],
            target=template["target"],
            port=template["port"],
            payload_size=template["payload_size"],
            params=template["params"],
        )
        self.pipeline.process_event(event)
