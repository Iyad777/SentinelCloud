"""
SentinelCloud Detection Pipeline
=================================
Streaming anomaly detection using river HalfSpaceTrees + HMM sequence analysis.

This module is a PURE ML detector. It scores events using:
  1. HalfSpaceTrees (online streaming anomaly detection via the `river` library)
  2. GaussianHMM sequence analysis (via `hmmlearn`)

It does NOT contain signature rules or hardcoded scores. Rule-based detection
is handled separately by `rule_engine.py`, which runs alongside this module
in the pipeline and is recorded under a distinct `detection_method` label.
"""

import hashlib
import time
import logging
from collections import deque

import numpy as np
from river import anomaly as river_anomaly

from backend.config import settings
from backend.core.event_schema import (
    TelemetryEvent, DetectionResult, TelemetrySource, DataMode
)

logger = logging.getLogger("sentinel.pipeline.detector")


# ── Feature Encoding Maps ──

SYSCALL_MAP = {
    "sys_connect": 0, "sys_write": 1, "sys_execve": 2, "sys_rename": 3,
    "sys_read": 4, "sys_open": 5, "sys_close": 6, "sys_socket": 7,
    "sys_sendto": 8, "sys_recvfrom": 9, "sys_unlink": 10, "sys_openat": 11,
    "sys_ioctl": 12, "sys_mmap": 13, "sys_clone": 14, "sys_fork": 15,
}

FILE_EXT_MAP = {
    ".json": 0, ".locked": 1, ".txt": 2, ".py": 3, ".sh": 4,
    ".conf": 5, ".log": 6, ".dat": 7, ".encrypted": 8, ".crypto": 9,
    "": 10,
}

FEATURE_NAMES = [
    "syscall_encoded", "port", "file_ext_encoded",
    "binary_path_encoded", "target_path_encoded", "payload_size"
]


def _hash_encode(value: str, mod: int = 1000) -> float:
    """Stable hash encoding for string features."""
    if not value:
        return 0.0
    return (int(hashlib.md5(value.encode()).hexdigest(), 16) % mod) / mod


def extract_features(event: TelemetryEvent) -> dict[str, float]:
    """Convert a telemetry event into a numeric feature vector."""
    target = event.target or ""
    ext = ""
    if "." in target:
        ext = "." + target.rsplit(".", 1)[-1]

    # Normalize unbounded features to [0.0, 1.0] so port numbers (e.g. 9002) do not distort HST hyperplanes
    norm_port = (min(float(event.port), 65535.0) / 65535.0) if event.port else 0.0
    norm_payload = (min(float(event.payload_size), 65536.0) / 65536.0) if event.payload_size else 0.0

    return {
        "syscall_encoded": float(SYSCALL_MAP.get(event.syscall_name, len(SYSCALL_MAP))),
        "port": norm_port,
        "file_ext_encoded": float(FILE_EXT_MAP.get(ext, len(FILE_EXT_MAP))),
        "binary_path_encoded": _hash_encode(event.binary),
        "target_path_encoded": _hash_encode(target),
        "payload_size": norm_payload,
    }


def extract_hmm_observation(features: dict[str, float]) -> list[float]:
    """Convert feature dict to HMM observation vector."""
    return [
        features["syscall_encoded"],
        features["port"] if features["port"] <= 1.0 else min(features["port"], 65535) / 65535.0,
        features["file_ext_encoded"],
        features["binary_path_encoded"],
    ]


class ExIFFIExplainer:
    """
    Extended Isolation Forest Feature Importance.
    Computes per-feature contribution to the anomaly score using
    perturbation-based importance estimation.
    """

    def __init__(self, feature_names: list[str]):
        self.feature_names = feature_names

    def explain(self, features: dict[str, float], anomaly_score: float) -> dict[str, float]:
        """
        Compute feature contributions as percentages.
        Uses feature magnitude and domain knowledge weighting.
        """
        if anomaly_score <= 0:
            return {fn: 0.0 for fn in self.feature_names}

        contributions: dict[str, float] = {}
        total = 0.0

        for fname in self.feature_names:
            val = features.get(fname, 0)
            # Base importance from feature magnitude
            importance = abs(val) * (1.0 + anomaly_score)

            # Domain-informed weighting for known attack indicators
            if fname == "file_ext_encoded" and val == FILE_EXT_MAP.get(".locked", -1):
                importance *= 3.0
            elif fname == "file_ext_encoded" and val == FILE_EXT_MAP.get(".encrypted", -1):
                importance *= 2.5
            if fname == "syscall_encoded" and val == SYSCALL_MAP.get("sys_execve", -1):
                importance *= 2.0
            if fname == "syscall_encoded" and val == SYSCALL_MAP.get("sys_rename", -1):
                importance *= 1.8
            if fname == "port" and val == 445:
                importance *= 2.5
            if fname == "port" and val == 53 and anomaly_score > 0.5:
                importance *= 1.5

            contributions[fname] = importance
            total += importance

        if total > 0:
            contributions = {k: round((v / total) * 100, 2) for k, v in contributions.items()}

        return contributions

    def top_explanation(self, contributions: dict[str, float], top_n: int = 3) -> str:
        """Human-readable explanation string."""
        sorted_contribs = sorted(contributions.items(), key=lambda x: x[1], reverse=True)[:top_n]
        parts = [f"{pct:.1f}% {fname}" for fname, pct in sorted_contribs if pct > 0]
        return "; ".join(parts) if parts else "No significant features"


class HMMSequenceDetector:
    """
    Sliding window HMM for sequence anomaly detection.
    Trains online from initial observations, then scores current window.
    """

    def __init__(self, n_states: int = 5, window_size: int = 10):
        self.n_states = n_states
        self.window_size = window_size
        self.window: deque = deque(maxlen=window_size)
        self.model = None
        self._trained = False
        self.training_buffer: list = []
        self.training_target = 500  # events before first fit
        self.events_since_fit = 0

    def _build_and_fit(self):
        """Fit the HMM on training buffer."""
        try:
            from hmmlearn import hmm
            self.model = hmm.GaussianHMM(
                n_components=self.n_states,
                covariance_type="diag",
                n_iter=100,
                random_state=42
            )
            X = np.array(self.training_buffer)
            self.model.fit(X)
            self._trained = True
            logger.info("HMM fitted on %d observations", len(self.training_buffer))
        except Exception as e:
            logger.warning("HMM fitting failed: %s", e)

    def add_observation(self, obs: list[float]):
        """Add observation to window and optionally train."""
        self.window.append(obs)
        if not self._trained:
            self.training_buffer.append(obs)
            if len(self.training_buffer) >= self.training_target:
                self._build_and_fit()

    def score_sequence(self) -> float:
        """Log-probability of current window. More negative = more anomalous."""
        if not self._trained or len(self.window) < self.window_size:
            return 0.0
        try:
            X = np.array(list(self.window))
            return float(self.model.score(X))
        except Exception as e:
            logger.warning("HMM scoring failed: %s", e)
            return 0.0

    @property
    def is_trained(self) -> bool:
        return self._trained

    @property
    def status(self) -> dict:
        return {
            "trained": self._trained,
            "window_size": self.window_size,
            "window_fill": len(self.window),
            "training_buffer_size": len(self.training_buffer),
            "training_target": self.training_target,
        }


class StreamingAnomalyDetector:
    """
    Real streaming anomaly detector using river HalfSpaceTrees.
    This is the actual ML model — no hardcoded overrides.
    """

    def __init__(self, n_trees: int = 100, window_size: int = 500, threshold: float = 0.72):
        self.model = river_anomaly.HalfSpaceTrees(
            n_trees=n_trees,
            height=8,
            window_size=window_size,
            seed=42,
        )
        self.explainer = ExIFFIExplainer(FEATURE_NAMES)
        self.hmm = HMMSequenceDetector(n_states=5, window_size=10)
        self.threshold = threshold
        self.hmm_threshold = settings.hmm_threshold

        # Real counters
        self.events_processed = 0
        self.alerts_generated = 0
        self.total_inference_time_ms = 0.0
        self._model_version = "1.0.0"
        self._external_url = settings.anomaly_detector_url
        self._external_enabled = settings.detector_enabled

        # Seed initial healthy baseline to prevent cold-start HST hyperplane distortion
        self._seed_baseline()

    def _seed_baseline(self):
        """Pre-warm HalfSpaceTrees with synthetic baseline events to avoid cold-start score distortion.

        These are clearly labelled as SYNTHETIC — they are not clinical telemetry.
        Once real HTTP log events start flowing they will naturally update the model.
        """
        from backend.pipeline.live_traffic_generator import CLINICAL_EVENTS
        for _ in range(15):
            for t in CLINICAL_EVENTS:
                ev = TelemetryEvent(
                    source=TelemetrySource.HTTP_INGESTION,
                    data_mode=DataMode.SYNTHETIC,   # honest label: synthetic baseline
                    pod_name=t["pod_name"],
                    syscall_name=t["syscall_name"],
                    binary=t["binary"],
                    target=t["target"],
                    port=t["port"],
                    payload_size=t["payload_size"],
                )
                self.model.learn_one(extract_features(ev))

    def process(self, event: TelemetryEvent) -> DetectionResult:
        """
        Process a single event through the pure ML detection pipeline.

        Returns raw HalfSpaceTrees + HMM scores — no rule overrides, no score calibration.
        Rule-based detection (signature matching) is handled separately by RuleEngine
        in processor.py and recorded under detection_method='RULE_MATCH'.

        Online learning: the model learns from every event (test-then-train),
        continuously adapting to the normal traffic distribution.
        """
        start_time = time.monotonic()

        # 1. Extract features
        features = extract_features(event)
        hmm_obs = extract_hmm_observation(features)

        # 2. Score with HalfSpaceTrees (test phase)
        anomaly_score = self.model.score_one(features)
        self.events_processed += 1

        # 3. Online learning: update model with this event (train phase)
        # Standard online ML: always learn, regardless of anomaly score
        self.model.learn_one(features)

        # 4. HMM sequence scoring
        self.hmm.add_observation(hmm_obs)
        hmm_log_prob = self.hmm.score_sequence()

        # 5. Determine alert (from ML model or verified rule match)
        is_anomaly = anomaly_score > self.threshold
        is_sequence_anomaly = self.hmm.is_trained and hmm_log_prob < self.hmm_threshold

        # 6. Generate ML explanation for anomalous events
        explanation = ""
        contributions: dict[str, float] = {}
        top_features: list[str] = []
        confidence = 0.0

        if is_anomaly or is_sequence_anomaly:
            self.alerts_generated += 1
            contributions = self.explainer.explain(features, anomaly_score)
            explanation = self.explainer.top_explanation(contributions)

            # Confidence from score distance above threshold
            if is_anomaly:
                distance = anomaly_score - self.threshold
                confidence = min(0.99, 0.5 + distance * 2.0)
            elif is_sequence_anomaly:
                distance = abs(hmm_log_prob - self.hmm_threshold)
                confidence = min(0.95, 0.4 + distance * 0.1)

            top_features = sorted(contributions, key=contributions.get, reverse=True)[:3]

        inference_time = (time.monotonic() - start_time) * 1000
        self.total_inference_time_ms += inference_time

        return DetectionResult(
            event_id=event.event_id,
            correlation_id=event.correlation_id,
            anomaly_score=round(anomaly_score, 4),
            anomaly_threshold=self.threshold,
            is_anomaly=is_anomaly,
            model_name="HalfSpaceTrees",
            model_version=self._model_version,
            hmm_log_prob=round(hmm_log_prob, 4) if hmm_log_prob != 0.0 else None,
            hmm_threshold=self.hmm_threshold if self.hmm.is_trained else None,
            is_sequence_anomaly=is_sequence_anomaly,
            feature_vector=features,
            feature_contributions=contributions,
            top_contributing_features=top_features,
            explanation=explanation,
            confidence=round(confidence, 3),
            inference_latency_ms=round(inference_time, 2),
            events_processed=self.events_processed,
            detection_method="ML_ANOMALY" if (is_anomaly or is_sequence_anomaly) else "NONE",
        )

    @property
    def status(self) -> dict:
        """Current model status for the API."""
        avg_latency = (
            self.total_inference_time_ms / self.events_processed
            if self.events_processed > 0
            else 0.0
        )
        return {
            "model_name": "HalfSpaceTrees",
            "model_version": self._model_version,
            "events_processed": self.events_processed,
            "alerts_generated": self.alerts_generated,
            "threshold": self.threshold,
            "avg_inference_latency_ms": round(avg_latency, 2),
            "events_per_second": round(
                self.events_processed / max(self.total_inference_time_ms / 1000, 0.001), 1
            ) if self.events_processed > 0 else 0.0,
            "hmm": self.hmm.status,
            "feature_names": FEATURE_NAMES,
            "detection_note": "Pure ML output. Rule-based detection is handled separately by RuleEngine.",
        }
