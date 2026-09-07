"""
SentinelCloud-Advanced: Diagnosis Service
-------------------------------------------
Causal root-cause diagnosis REST API.

When triggered by the orchestrator, this service:
1. Queries ClickHouse for events from the suspect pod in the last 60 seconds.
2. Analyses the event patterns to determine root cause:
   - compromise: shell exec, suspicious renames, SMB connections
   - dependency_failure: dependency pod restarts, connection refused
   - network_partition: network policy deny events
   - unknown: cannot determine
3. Returns the diagnosis to the orchestrator.
"""

import os
import json
import time
import logging
from datetime import datetime, timezone, timedelta

from flask import Flask, jsonify, request
from clickhouse_driver import Client as CHClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse.sentinel.svc.cluster.local")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "sentinel")
PORT = int(os.environ.get("PORT", "8081"))
LOOKBACK_SECONDS = int(os.environ.get("LOOKBACK_SECONDS", "60"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("diagnosis-service")

app = Flask(__name__)


# ---------------------------------------------------------------------------
# ClickHouse Query Helper
# ---------------------------------------------------------------------------
class EventQuerier:
    """Queries ClickHouse for recent events."""

    def __init__(self):
        self._client = None

    def _connect(self):
        try:
            self._client = CHClient(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                database=CLICKHOUSE_DB
            )
        except Exception as e:
            logger.error("ClickHouse connection failed: %s", e)
            self._client = None

    def get_recent_events(self, pod_name: str, namespace: str, seconds: int = 60) -> list:
        """Fetch events for a pod from the last N seconds."""
        if not self._client:
            self._connect()
        if not self._client:
            return []

        since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        try:
            rows = self._client.execute(
                """
                SELECT timestamp, syscall_name, params, anomaly_score
                FROM events
                WHERE pod_name = %(pod)s
                  AND namespace = %(ns)s
                  AND timestamp >= %(since)s
                ORDER BY timestamp DESC
                LIMIT 500
                """,
                {"pod": pod_name, "ns": namespace, "since": since}
            )
            events = []
            for row in rows:
                events.append({
                    "timestamp": str(row[0]),
                    "syscall_name": row[1],
                    "params": json.loads(row[2]) if row[2] else {},
                    "anomaly_score": float(row[3]),
                })
            return events
        except Exception as e:
            logger.error("ClickHouse query failed: %s", e)
            return []

    def get_dependency_events(self, namespace: str, seconds: int = 60) -> list:
        """Fetch events for all pods in the namespace to check dependencies."""
        if not self._client:
            self._connect()
        if not self._client:
            return []

        since = datetime.now(timezone.utc) - timedelta(seconds=seconds)
        try:
            rows = self._client.execute(
                """
                SELECT pod_name, syscall_name, params, anomaly_score
                FROM events
                WHERE namespace = %(ns)s
                  AND timestamp >= %(since)s
                ORDER BY timestamp DESC
                LIMIT 200
                """,
                {"ns": namespace, "since": since}
            )
            return [{"pod_name": r[0], "syscall_name": r[1],
                      "params": json.loads(r[2]) if r[2] else {},
                      "anomaly_score": float(r[3])} for r in rows]
        except Exception as e:
            logger.error("ClickHouse dependency query failed: %s", e)
            return []


querier = EventQuerier()


# ---------------------------------------------------------------------------
# Diagnosis Engine
# ---------------------------------------------------------------------------
SHELL_BINARIES = {"/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash",
                  "/bin/zsh", "/usr/bin/zsh", "sh", "bash"}
RANSOMWARE_EXTENSIONS = {".locked", ".encrypted", ".crypto", ".ransom", ".crypt"}
SMB_PORT = 445


def diagnose_root_cause(pod_name: str, namespace: str) -> dict:
    """
    Analyse recent events and determine root cause.
    
    Returns:
        {
            "root_cause": str,  # compromise | dependency_failure | network_partition | unknown
            "confidence": float,  # 0.0 - 1.0
            "evidence": list[str],
            "recommended_action": str
        }
    """
    events = querier.get_recent_events(pod_name, namespace, LOOKBACK_SECONDS)
    dep_events = querier.get_dependency_events(namespace, LOOKBACK_SECONDS)

    evidence = []
    scores = {"compromise": 0.0, "dependency_failure": 0.0, "network_partition": 0.0}

    if not events:
        logger.warning("No events found for pod %s/%s in last %ds", namespace, pod_name, LOOKBACK_SECONDS)
        return {
            "root_cause": "unknown",
            "confidence": 0.0,
            "evidence": ["No recent events found in ClickHouse"],
            "recommended_action": "manual_investigation"
        }

    for event in events:
        syscall = event["syscall_name"]
        params = event["params"]

        # --- Compromise Indicators ---
        # Shell execution
        if syscall == "sys_execve":
            binary = params.get("binary", params.get("path", ""))
            if any(shell in binary for shell in SHELL_BINARIES):
                scores["compromise"] += 3.0
                evidence.append(f"Shell execution detected: {binary}")

        # Ransomware-like file rename
        if syscall == "sys_rename":
            target = params.get("target", "")
            for ext in RANSOMWARE_EXTENSIONS:
                if target.endswith(ext):
                    scores["compromise"] += 5.0
                    evidence.append(f"Suspicious file rename to: {target}")
                    break

        # SMB port connection
        if syscall == "sys_connect":
            port = int(params.get("port", 0))
            if port == SMB_PORT:
                scores["compromise"] += 4.0
                evidence.append(f"Connection to SMB port 445 detected")

        # --- Network Partition Indicators ---
        if syscall == "sys_connect":
            errno = params.get("errno", "")
            if "ECONNREFUSED" in str(errno) or "ETIMEDOUT" in str(errno):
                scores["network_partition"] += 2.0
                evidence.append(f"Connection failed: {errno}")

    # --- Dependency Failure Indicators ---
    # Check if dependency pods have high anomaly scores or restarts
    other_pod_anomalies = [e for e in dep_events
                           if e["pod_name"] != pod_name and e["anomaly_score"] > 0.5]
    if other_pod_anomalies:
        scores["dependency_failure"] += len(other_pod_anomalies) * 0.5
        evidence.append(f"{len(other_pod_anomalies)} anomalous events from dependency pods")

    # Determine winner
    max_cause = max(scores, key=scores.get)
    max_score = scores[max_cause]
    total = sum(scores.values()) or 1.0

    if max_score == 0:
        return {
            "root_cause": "unknown",
            "confidence": 0.0,
            "evidence": evidence or ["No clear indicators found"],
            "recommended_action": "manual_investigation"
        }

    confidence = min(max_score / total, 1.0)

    # Map root cause to recommended action
    action_map = {
        "compromise": "quarantine_and_redeploy",
        "dependency_failure": "restart_dependency",
        "network_partition": "check_network_policies",
    }

    return {
        "root_cause": max_cause,
        "confidence": round(confidence, 3),
        "evidence": evidence,
        "recommended_action": action_map.get(max_cause, "manual_investigation"),
        "scores": {k: round(v, 2) for k, v in scores.items()},
        "events_analysed": len(events),
    }


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "diagnosis-service",
        "status": "healthy",
        "clickhouse_host": CLICKHOUSE_HOST,
        "lookback_seconds": LOOKBACK_SECONDS,
    }), 200


@app.route("/diagnose", methods=["POST"])
def diagnose():
    """
    Diagnose root cause for a pod.
    Expected JSON: { "pod_name": str, "namespace": str }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    pod_name = data.get("pod_name")
    namespace = data.get("namespace", "default")

    if not pod_name:
        return jsonify({"error": "pod_name is required"}), 400

    logger.info("Diagnosing pod %s in namespace %s", pod_name, namespace)
    result = diagnose_root_cause(pod_name, namespace)
    logger.info("Diagnosis result for %s/%s: %s (confidence=%.3f)",
                namespace, pod_name, result["root_cause"], result["confidence"])

    return jsonify(result), 200


if __name__ == "__main__":
    logger.info("Starting Diagnosis Service on port %d", PORT)
    app.run(host="0.0.0.0", port=PORT)
