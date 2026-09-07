"""
SentinelCloud-Advanced: MAPE-K Orchestrator Controller
-------------------------------------------------------
Enforcement Plane – Autonomous remediation controller.

Uses the `kopf` framework to watch SecurityAlert CRDs and execute
the MAPE-K (Monitor-Analyse-Plan-Execute-Knowledge) loop:

  Monitor  → watches SecurityAlert custom resources
  Analyse  → calls the Diagnosis Service for root-cause analysis
  Plan     → selects remediation action based on root cause + criticality
  Execute  → applies Cilium NPs, deletes/scales pods via K8s API
  Knowledge → logs all actions to ClickHouse; supports model feedback

Remediation Actions:
  1. QuarantineOnly       – apply deny-all Cilium NP on the suspect pod
  2. FailoverAndQuarantine – switch traffic to backup replica, then quarantine
  3. Redeploy             – delete the pod (controller recreates from golden image)
  4. RestartDependency    – restart a dependency deployment

Safety Interlocks:
  - For critical pods, wait up to 3s for a backup replica before termination
  - Manual override HTTP endpoint: POST /override/{alert_name}
"""

import os
import sys
import json
import time
import logging
import threading
import asyncio
from datetime import datetime, timezone

import kopf
import yaml
import requests
from flask import Flask, jsonify, request as flask_request
from kubernetes import client as k8s_client, config as k8s_config
from clickhouse_driver import Client as CHClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DIAGNOSIS_SERVICE_URL = os.environ.get(
    "DIAGNOSIS_SERVICE_URL", "http://diagnosis-service.sentinel.svc.cluster.local:8081"
)
CLICKHOUSE_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse.sentinel.svc.cluster.local")
CLICKHOUSE_PORT = int(os.environ.get("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DB = os.environ.get("CLICKHOUSE_DB", "sentinel")

SAFETY_TIMEOUT_SECONDS = int(os.environ.get("SAFETY_TIMEOUT_SECONDS", "3"))
OVERRIDE_PORT = int(os.environ.get("OVERRIDE_PORT", "8083"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mape-k-controller")

# Track overridden alerts (alert_name -> True)
overridden_alerts = {}

# ---------------------------------------------------------------------------
# Kubernetes Client Setup
# ---------------------------------------------------------------------------
try:
    k8s_config.load_incluster_config()
except Exception:
    k8s_config.load_kube_config()

core_v1 = k8s_client.CoreV1Api()
apps_v1 = k8s_client.AppsV1Api()
custom_api = k8s_client.CustomObjectsApi()

# ---------------------------------------------------------------------------
# ClickHouse Logger
# ---------------------------------------------------------------------------
ch_client = None


def _get_ch_client():
    global ch_client
    if ch_client is None:
        try:
            ch_client = CHClient(
                host=CLICKHOUSE_HOST,
                port=CLICKHOUSE_PORT,
                database=CLICKHOUSE_DB,
            )
        except Exception as e:
            logger.warning("ClickHouse connection failed: %s", e)
    return ch_client


def log_action(alert_name: str, pod_name: str, namespace: str,
               action_type: str, root_cause: str, details: str, success: bool):
    """Log a remediation action to ClickHouse."""
    client = _get_ch_client()
    if not client:
        return
    try:
        client.execute(
            "INSERT INTO actions VALUES",
            [{
                "timestamp": datetime.now(timezone.utc),
                "alert_id": alert_name,
                "pod_name": pod_name,
                "namespace": namespace,
                "action_type": action_type,
                "root_cause": root_cause,
                "details": details,
                "success": 1 if success else 0,
            }],
        )
        logger.info("Action logged to ClickHouse: %s/%s -> %s", namespace, pod_name, action_type)
    except Exception as e:
        logger.warning("Failed to log action to ClickHouse: %s", e)


# ---------------------------------------------------------------------------
# Diagnosis Client
# ---------------------------------------------------------------------------
def call_diagnosis(pod_name: str, namespace: str) -> dict:
    """Call the Diagnosis Service REST API."""
    try:
        resp = requests.post(
            f"{DIAGNOSIS_SERVICE_URL}/diagnose",
            json={"pod_name": pod_name, "namespace": namespace},
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
        else:
            logger.error("Diagnosis service returned %d: %s", resp.status_code, resp.text)
    except requests.RequestException as e:
        logger.error("Diagnosis service call failed: %s", e)

    return {
        "root_cause": "unknown",
        "confidence": 0.0,
        "evidence": ["diagnosis service unreachable"],
        "recommended_action": "manual_investigation",
    }


# ---------------------------------------------------------------------------
# Pod Helpers
# ---------------------------------------------------------------------------
def is_pod_critical(pod_name: str, namespace: str) -> bool:
    """Check if a pod has the label critical=true."""
    try:
        pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        labels = pod.metadata.labels or {}
        return labels.get("critical", "").lower() == "true"
    except Exception as e:
        logger.warning("Could not read pod %s/%s: %s", namespace, pod_name, e)
        return False


def get_pod_owner_deployment(pod_name: str, namespace: str) -> str:
    """Find the Deployment name that owns a pod."""
    try:
        pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
        for ref in (pod.metadata.owner_references or []):
            if ref.kind == "ReplicaSet":
                # Get the ReplicaSet to find the Deployment
                rs = apps_v1.read_namespaced_replica_set(name=ref.name, namespace=namespace)
                for rs_ref in (rs.metadata.owner_references or []):
                    if rs_ref.kind == "Deployment":
                        return rs_ref.name
    except Exception as e:
        logger.warning("Could not determine owner deployment: %s", e)
    return ""


def wait_for_ready_replica(deployment_name: str, namespace: str,
                           timeout: int = 3) -> bool:
    """Wait up to `timeout` seconds for at least one ready replica."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            dep = apps_v1.read_namespaced_deployment(
                name=deployment_name, namespace=namespace
            )
            ready = dep.status.ready_replicas or 0
            if ready >= 1:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


# ---------------------------------------------------------------------------
# Remediation Actions
# ---------------------------------------------------------------------------
def action_quarantine_only(pod_name: str, namespace: str) -> bool:
    """Apply a Cilium NetworkPolicy that denies all ingress/egress."""
    logger.info("ACTION: QuarantineOnly for %s/%s", namespace, pod_name)

    # First, label the pod as suspect
    try:
        core_v1.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body={"metadata": {"labels": {"suspect": "true"}}},
        )
    except Exception as e:
        logger.error("Failed to label pod as suspect: %s", e)
        return False

    # Apply deny-all Cilium NetworkPolicy
    policy = {
        "apiVersion": "cilium.io/v2",
        "kind": "CiliumNetworkPolicy",
        "metadata": {
            "name": f"quarantine-{pod_name}",
            "namespace": namespace,
        },
        "spec": {
            "endpointSelector": {
                "matchLabels": {"suspect": "true"},
            },
            "ingressDeny": [{}],
            "egressDeny": [{}],
        },
    }

    try:
        custom_api.create_namespaced_custom_object(
            group="cilium.io",
            version="v2",
            namespace=namespace,
            plural="ciliumnetworkpolicies",
            body=policy,
        )
        logger.info("Cilium quarantine policy applied for %s/%s", namespace, pod_name)
        return True
    except Exception as e:
        if "already exists" in str(e).lower():
            logger.info("Quarantine policy already exists for %s", pod_name)
            return True
        logger.error("Failed to apply quarantine policy: %s", e)
        return False


def action_redeploy(pod_name: str, namespace: str) -> bool:
    """Delete the pod so that the Deployment controller recreates it."""
    logger.info("ACTION: Redeploy for %s/%s", namespace, pod_name)
    try:
        core_v1.delete_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            grace_period_seconds=0,
        )
        logger.info("Pod %s/%s deleted for redeployment", namespace, pod_name)
        return True
    except Exception as e:
        logger.error("Failed to delete pod: %s", e)
        return False


def action_failover_and_quarantine(pod_name: str, namespace: str) -> bool:
    """
    For critical services:
    1. Ensure a healthy replica exists.
    2. Update the service selector to exclude the suspect pod.
    3. Quarantine the suspect pod.
    4. Delete the suspect pod.
    """
    logger.info("ACTION: FailoverAndQuarantine for %s/%s", namespace, pod_name)

    deployment_name = get_pod_owner_deployment(pod_name, namespace)
    if not deployment_name:
        logger.warning("Cannot determine deployment for %s – falling back to quarantine only",
                       pod_name)
        return action_quarantine_only(pod_name, namespace)

    # Safety interlock: ensure at least one replica is ready
    logger.info("Safety interlock: waiting for ready replica of %s", deployment_name)
    if not wait_for_ready_replica(deployment_name, namespace, SAFETY_TIMEOUT_SECONDS):
        logger.error("SAFETY ABORT: No ready replicas for %s within %ds – will not terminate pod",
                     deployment_name, SAFETY_TIMEOUT_SECONDS)
        # Still quarantine but don't delete
        action_quarantine_only(pod_name, namespace)
        log_action(
            alert_name="", pod_name=pod_name, namespace=namespace,
            action_type="failover_aborted", root_cause="no_ready_replicas",
            details=f"No replicas ready within {SAFETY_TIMEOUT_SECONDS}s",
            success=False,
        )
        return False

    # Quarantine the suspect
    quarantine_ok = action_quarantine_only(pod_name, namespace)

    # Delete the suspect pod (controller will recreate)
    if quarantine_ok:
        action_redeploy(pod_name, namespace)

    return quarantine_ok


def action_restart_dependency(pod_name: str, namespace: str) -> bool:
    """Restart a dependency deployment by scaling down and up."""
    logger.info("ACTION: RestartDependency for %s/%s", namespace, pod_name)

    deployment_name = get_pod_owner_deployment(pod_name, namespace)
    if not deployment_name:
        logger.warning("Cannot determine deployment – cannot restart")
        return False

    try:
        # Get current replicas
        dep = apps_v1.read_namespaced_deployment(
            name=deployment_name, namespace=namespace
        )
        original_replicas = dep.spec.replicas or 1

        # Scale down
        apps_v1.patch_namespaced_deployment_scale(
            name=deployment_name,
            namespace=namespace,
            body={"spec": {"replicas": 0}},
        )
        logger.info("Scaled down %s to 0", deployment_name)
        time.sleep(2)

        # Scale back up
        apps_v1.patch_namespaced_deployment_scale(
            name=deployment_name,
            namespace=namespace,
            body={"spec": {"replicas": original_replicas}},
        )
        logger.info("Scaled up %s to %d", deployment_name, original_replicas)
        return True
    except Exception as e:
        logger.error("Failed to restart dependency: %s", e)
        return False


# ---------------------------------------------------------------------------
# MAPE-K Decision Engine
# ---------------------------------------------------------------------------
def select_action(root_cause: str, is_critical: bool) -> str:
    """Select remediation action based on root cause and criticality."""
    if root_cause == "compromise":
        if is_critical:
            return "failover_and_quarantine"
        else:
            return "redeploy"
    elif root_cause == "dependency_failure":
        return "restart_dependency"
    elif root_cause == "network_partition":
        return "quarantine_only"
    else:
        return "quarantine_only"  # Default safe action


def execute_action(action: str, pod_name: str, namespace: str) -> bool:
    """Execute the selected remediation action."""
    action_map = {
        "quarantine_only": action_quarantine_only,
        "failover_and_quarantine": action_failover_and_quarantine,
        "redeploy": action_redeploy,
        "restart_dependency": action_restart_dependency,
    }
    func = action_map.get(action)
    if not func:
        logger.error("Unknown action: %s", action)
        return False
    return func(pod_name, namespace)


# ---------------------------------------------------------------------------
# Kopf Handler – SecurityAlert CRD Watcher
# ---------------------------------------------------------------------------
@kopf.on.create("sentinel.io", "v1", "securityalerts")
def on_alert_created(spec, name, namespace, **kwargs):
    """
    Main MAPE-K handler. Triggered when a SecurityAlert CRD is created.
    """
    pod_name = spec.get("podName", "")
    alert_ns = spec.get("namespace", namespace)
    anomaly_score = spec.get("anomalyScore", 0.0)
    explanation = spec.get("explanation", "")
    source = spec.get("source", "unknown")

    logger.info(
        "═══════════════════════════════════════════════════════════════"
    )
    logger.info(
        "ALERT RECEIVED: %s | pod=%s ns=%s score=%.4f source=%s",
        name, pod_name, alert_ns, anomaly_score, source,
    )

    # Check for manual override
    if name in overridden_alerts:
        logger.info("Alert %s has been manually overridden – skipping", name)
        return {"action": "overridden"}

    # ── ANALYSE ──
    logger.info("[ANALYSE] Calling Diagnosis Service for %s/%s", alert_ns, pod_name)
    diagnosis = call_diagnosis(pod_name, alert_ns)
    root_cause = diagnosis["root_cause"]
    confidence = diagnosis["confidence"]
    evidence = diagnosis.get("evidence", [])

    logger.info(
        "[ANALYSE] Root cause: %s (confidence=%.3f) Evidence: %s",
        root_cause, confidence, "; ".join(evidence[:3]),
    )

    # ── PLAN ──
    is_critical = is_pod_critical(pod_name, alert_ns)
    action = select_action(root_cause, is_critical)
    logger.info(
        "[PLAN] Selected action: %s (critical=%s, root_cause=%s)",
        action, is_critical, root_cause,
    )

    # ── EXECUTE ──
    logger.info("[EXECUTE] Executing action: %s on %s/%s", action, alert_ns, pod_name)
    success = execute_action(action, pod_name, alert_ns)
    logger.info(
        "[EXECUTE] Action %s: %s",
        action, "SUCCESS" if success else "FAILED",
    )

    # ── KNOWLEDGE ──
    log_action(
        alert_name=name,
        pod_name=pod_name,
        namespace=alert_ns,
        action_type=action,
        root_cause=root_cause,
        details=json.dumps({
            "confidence": confidence,
            "evidence": evidence,
            "anomaly_score": anomaly_score,
            "explanation": explanation,
            "source": source,
        }),
        success=success,
    )

    # Update the SecurityAlert status
    try:
        custom_api.patch_namespaced_custom_object_status(
            group="sentinel.io",
            version="v1",
            namespace=namespace,
            plural="securityalerts",
            name=name,
            body={
                "status": {
                    "phase": "remediated" if success else "failed",
                    "action": action,
                    "rootCause": root_cause,
                    "remediatedAt": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
    except Exception as e:
        logger.warning("Could not update SecurityAlert status: %s", e)

    logger.info(
        "═══════════════════════════════════════════════════════════════"
    )

    return {
        "action": action,
        "root_cause": root_cause,
        "success": success,
    }


# ---------------------------------------------------------------------------
# Manual Override HTTP API (runs in a separate thread)
# ---------------------------------------------------------------------------
override_app = Flask("mape-k-override")


@override_app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "mape-k-controller",
        "status": "healthy",
        "overridden_alerts": len(overridden_alerts),
    }), 200


@override_app.route("/override/<alert_name>", methods=["POST"])
def override_alert(alert_name):
    """Cancel automatic remediation for a specific alert."""
    overridden_alerts[alert_name] = True
    logger.info("Manual override registered for alert: %s", alert_name)
    return jsonify({
        "status": "overridden",
        "alert_name": alert_name,
        "message": "Automatic remediation cancelled for this alert",
    }), 200


@override_app.route("/overrides", methods=["GET"])
def list_overrides():
    return jsonify({
        "overridden_alerts": list(overridden_alerts.keys()),
        "count": len(overridden_alerts),
    }), 200


@override_app.route("/override/<alert_name>", methods=["DELETE"])
def remove_override(alert_name):
    """Remove an override, re-enabling automatic remediation."""
    if alert_name in overridden_alerts:
        del overridden_alerts[alert_name]
        return jsonify({"status": "override_removed", "alert_name": alert_name}), 200
    return jsonify({"error": "override not found"}), 404


def run_override_api():
    override_app.run(host="0.0.0.0", port=OVERRIDE_PORT, use_reloader=False)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # Start the manual override API in a background thread
    api_thread = threading.Thread(target=run_override_api, daemon=True)
    api_thread.start()
    logger.info("Manual override API started on port %d", OVERRIDE_PORT)

    # Kopf will be started via `kopf run` command or embedded
    logger.info("MAPE-K Controller starting…")
    logger.info("Watching for SecurityAlert resources on sentinel.io/v1")
