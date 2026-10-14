"""
Falco Webhook Receiver
======================
Receives Falco JSON alerts via HTTP webhook and converts them to
TelemetryEvent objects (source=FALCO, data_mode=LIVE) for the detection
pipeline. Runs on the Mac backend; Falco runs on the UTM Ubuntu VM and
POSTs here.

Example Falco alert:
{
  "rule": "Unauthorized shell in medical container",
  "priority": "WARNING",
  "output_fields": {
    "container.name": "ehr", "proc.name": "bash",
    "proc.args": "-c whoami", "evt.type": "execve", ...
  }
}
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException

from backend.config import settings
from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode

logger = logging.getLogger("sentinel.integrations.falco")

falco_router = APIRouter(prefix="/api/falco", tags=["falco"])

# Falco evt.type -> our syscall abstraction
SYSCALL_MAP = {
    "execve": "sys_execve",
    "connect": "sys_connect",
    "open": "sys_openat",
    "openat": "sys_openat",
    "rename": "sys_rename",
    "renameat": "sys_rename",
    "write": "sys_write",
    "read": "sys_read",
    "sendto": "sys_sendto",
    "recvfrom": "sys_recvfrom",
    "unlink": "sys_unlink",
    "socket": "sys_socket",
    "clone": "sys_clone",
}


def _falco_to_telemetry_event(alert: dict) -> Optional[TelemetryEvent]:
    """Convert a Falco JSON alert to a TelemetryEvent. None if unparsable."""
    if not isinstance(alert, dict):
        return None
    fields = alert.get("output_fields", {}) or {}
    if not isinstance(fields, dict):
        fields = {}
    container = str(fields.get("container.name", "") or "")
    evt_type = str(fields.get("evt.type", "") or "")
    proc_name = str(fields.get("proc.name", "") or "")
    proc_args = str(fields.get("proc.args", "") or fields.get("proc.cmdline", "") or "")
    fd_name = str(fields.get("fd.name", "") or fields.get("fd.sip", "") or "")
    try:
        port = int(fields.get("fd.sport", 0) or 0)
    except (TypeError, ValueError):
        port = 0
    if not (container or proc_name or fd_name or evt_type):
        return None  # not a usable Falco alert
    return TelemetryEvent(
        source=TelemetrySource.FALCO,
        data_mode=DataMode.LIVE,
        pod_name=container or "unknown",
        namespace="medical",
        syscall_name=SYSCALL_MAP.get(evt_type, evt_type or "sys_read"),
        binary=f"/proc/{fields.get('proc.pid', '?')}/exe ({proc_name})" if proc_name else "",
        target=fd_name or proc_args,
        port=port,
        params={
            "falco_rule": alert.get("rule", ""),
            "falco_priority": alert.get("priority", ""),
            "proc_args": proc_args,
            "container_image": fields.get("container.image.repository", ""),
        },
    )


@falco_router.post("/webhook")
async def falco_webhook(payload: dict, x_falco_token: Optional[str] = Header(default=None)):
    """Receive a Falco alert and inject it into the detection pipeline."""
    from backend.pipeline.processor import pipeline

    if not getattr(settings, "falco_enabled", False):
        raise HTTPException(status_code=503, detail="Falco receiver disabled (SENTINEL_FALCO_ENABLED=false)")
    expected = getattr(settings, "falco_webhook_token", "") or ""
    if expected and x_falco_token != expected:
        raise HTTPException(status_code=401, detail="Invalid Falco webhook token")
    event = _falco_to_telemetry_event(payload)
    if event is None:
        return {"accepted": False, "reason": "Could not parse Falco alert"}
    detection = pipeline.process_event(event)
    logger.info("Falco alert ingested: rule=%s pod=%s method=%s",
                payload.get("rule", "?"), event.pod_name, detection.detection_method)
    return {
        "accepted": True,
        "event_id": event.event_id,
        "anomaly_score": detection.anomaly_score,
        "detection_method": detection.detection_method,
        "rule_id": detection.rule_id,
    }


@falco_router.get("/status")
async def falco_status():
    """Whether the Falco webhook receiver is enabled."""
    return {
        "enabled": bool(getattr(settings, "falco_enabled", False)),
        "endpoint": "/api/falco/webhook",
        "token_required": bool(getattr(settings, "falco_webhook_token", "")),
    }
