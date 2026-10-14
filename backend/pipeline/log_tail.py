"""
SentinelCloud Log Tail Ingester
===============================
Real telemetry source: tails structured JSON access logs written by the
medical Flask services (vitals, drug-dispenser, ehr, billing) and converts
each log line into a TelemetryEvent with source=HTTP_LOG / data_mode=HTTP_LOG.

Each medical service logs lines like:
  {"timestamp": "...", "level": "INFO", "message": "Request completed",
   "method": "GET", "path": "/record", "status": 200, "latency_ms": 4.2}

Runs as daemon threads alongside the backend (see backend/main.py lifespan).
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from backend.config import settings
from backend.core.event_schema import TelemetryEvent, TelemetrySource, DataMode

logger = logging.getLogger("sentinel.pipeline.log_tail")


def http_to_syscall(method: str, path: str) -> str:
    """Map HTTP method+path to the syscall abstraction used by the schema."""
    method = (method or "GET").upper()
    path = (path or "/").split("?")[0]
    if method == "DELETE":
        return "sys_unlink"  # suspicious — DELETE not used normally
    if method == "POST" and "login" in path.lower():
        return "sys_connect"
    if method == "POST":
        return "sys_write"
    return "sys_read"


SERVICE_DEFAULTS = {
    "ehr": {"port": 5002, "binary": "/usr/local/bin/gunicorn"},
    "vitals": {"port": 5000, "binary": "/app/vitals_collector"},
    "billing": {"port": 5003, "binary": "/usr/bin/billing_api"},
    "drug-dispenser": {"port": 5001, "binary": "/usr/bin/dispenser_srv"},
}


@dataclass
class LogTailConfig:
    """Per-service tail configuration."""

    pod_name: str
    log_path: str
    port: int = 0
    binary: str = ""


@dataclass
class LogLine:
    """A parsed medical-service JSON log line."""

    method: str = "GET"
    path: str = "/"
    status: int = 200
    latency_ms: float = 0.0
    extra: dict = field(default_factory=dict)

class MedicalLogParser:
    """Parses a raw JSON log line into a LogLine. None if unparsable."""

    @staticmethod
    def parse(raw: str) -> Optional[LogLine]:
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            return None
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None
        if "method" not in obj and "path" not in obj:
            return None  # not an access-log line (e.g. startup banner)
        try:
            return LogLine(
                method=str(obj.get("method", "GET")),
                path=str(obj.get("path", "/")),
                status=int(obj.get("status", 200)),
                latency_ms=float(obj.get("latency_ms", 0.0)),
                extra={k: v for k, v in obj.items()
                       if k not in ("timestamp", "level", "logger", "message",
                                    "method", "path", "status", "latency_ms")},
            )
        except (TypeError, ValueError):
            return None

    @staticmethod
    def to_event(line: LogLine, cfg: LogTailConfig) -> TelemetryEvent:
        """Convert a parsed LogLine into a TelemetryEvent (HTTP_LOG)."""
        syscall = http_to_syscall(line.method, line.path)
        payload = int(line.extra.get("content_length", 0) or 0)
        return TelemetryEvent(
            source=TelemetrySource.HTTP_LOG,
            data_mode=DataMode.HTTP_LOG,
            pod_name=cfg.pod_name,
            namespace="medical",
            syscall_name=syscall,
            binary=cfg.binary,
            target=line.path,
            port=cfg.port,
            payload_size=payload,
            params={"method": line.method, "path": line.path,
                    "status": line.status, "latency_ms": line.latency_ms,
                    **line.extra},
        )


class ServiceLogTailer:
    """Tails one service log file, feeding parsed events to the pipeline."""

    def __init__(self, cfg: LogTailConfig, pipeline):
        self.cfg = cfg
        self.pipeline = pipeline
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.events_tailed = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, daemon=True, name=f"logtail-{self.cfg.pod_name}")
        self._thread.start()
        logger.info("Log tailer started: pod=%s path=%s",
                    self.cfg.pod_name, self.cfg.log_path)

    def stop(self):
        self._stop.set()

    def _run(self):
        path = Path(self.cfg.log_path)
        while not self._stop.is_set() and not path.exists():
            time.sleep(2.0)  # services may start after backend
        if self._stop.is_set():
            return
        try:
            with open(path, "r") as fh:
                fh.seek(0, 2)  # EOF: only new lines are real telemetry
                while not self._stop.is_set():
                    line = fh.readline()
                    if not line:
                        time.sleep(0.25)
                        continue
                    parsed = MedicalLogParser.parse(line)
                    if parsed is None:
                        continue
                    try:
                        event = MedicalLogParser.to_event(parsed, self.cfg)
                        self.pipeline.process_event(event)
                        self.events_tailed += 1
                    except Exception as e:
                        logger.warning("LogTail process_event failed: %s", e)
        except Exception as e:
            logger.error("LogTailer %s error: %s", self.cfg.pod_name, e)


class LogTailIngester:
    """Manages tailers for all four medical services. No-op when disabled."""

    def __init__(self, pipeline):
        log_paths = {
            "ehr": getattr(settings, "ehr_log_path", "./data/ehr.log"),
            "vitals": getattr(settings, "vitals_log_path", "./data/vitals.log"),
            "billing": getattr(settings, "billing_log_path", "./data/billing.log"),
            "drug-dispenser": getattr(
                settings, "drug_dispenser_log_path", "./data/dispenser.log"),
        }
        self.pipeline = pipeline
        self.tailers = [
            ServiceLogTailer(
                LogTailConfig(pod_name=pod, log_path=log_paths[pod],
                              port=SERVICE_DEFAULTS[pod]["port"],
                              binary=SERVICE_DEFAULTS[pod]["binary"]),
                pipeline,
            )
            for pod in ("ehr", "vitals", "billing", "drug-dispenser")
        ]

    def start(self):
        if not getattr(settings, "log_tail_enabled", True):
            logger.info("Log tail ingester disabled via config")
            return
        for t in self.tailers:
            t.start()

    def stop(self):
        for t in self.tailers:
            t.stop()

    @property
    def events_tailed(self) -> int:
        return sum(t.events_tailed for t in self.tailers)
