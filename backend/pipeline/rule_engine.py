"""
SentinelCloud Rule Engine
=========================
Deterministic signature-based detection.

This module is EXPLICITLY separate from the ML anomaly detector (detector.py).
It matches known attack patterns using deterministic rules and returns a RuleMatch
object when a pattern is found.

In the pipeline (processor.py) both the rule engine and the ML detector are run
independently. The detection_method field on DetectionResult records which fired:
  - "RULE_MATCH"  — only this rule engine fired
  - "ML_ANOMALY"  — only the HalfSpaceTrees model fired
  - "BOTH"        — both fired
  - "NONE"        — neither fired

Rules are derived from the attack patterns in the 7 testing scenarios.
Each rule maps to a MITRE ATT&CK technique.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from backend.core.event_schema import TelemetryEvent

logger = logging.getLogger("sentinel.pipeline.rule_engine")


# ── Rule Match Result ──

@dataclass
class RuleMatch:
    """Result returned when a rule fires."""
    rule_id: str             # e.g. "RANSOM_001"
    rule_name: str           # e.g. "Ransomware: file rename to encrypted extension"
    mitre_technique_id: str  # e.g. "T1486"
    mitre_technique_name: str
    confidence: float        # 0.0–1.0
    explanation: str         # Human-readable explanation for the SOC analyst
    severity: str            # "CRITICAL" | "HIGH" | "MEDIUM"


# ── Individual Rule Definitions ──

class _Rule:
    """Base class for a detection rule."""
    rule_id: str
    rule_name: str
    mitre_technique_id: str
    mitre_technique_name: str
    confidence: float
    severity: str

    def matches(self, event: TelemetryEvent) -> bool:
        raise NotImplementedError

    def explain(self, event: TelemetryEvent) -> str:
        raise NotImplementedError

    def to_match(self, event: TelemetryEvent) -> RuleMatch:
        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.rule_name,
            mitre_technique_id=self.mitre_technique_id,
            mitre_technique_name=self.mitre_technique_name,
            confidence=self.confidence,
            explanation=self.explain(event),
            severity=self.severity,
        )


class _RansomwareRule(_Rule):
    """RANSOM_001 — Detect file rename to a ransomware extension."""
    rule_id = "RANSOM_001"
    rule_name = "Ransomware: file rename to encrypted extension"
    mitre_technique_id = "T1486"
    mitre_technique_name = "Data Encrypted for Impact"
    confidence = 0.97
    severity = "CRITICAL"

    _EXTENSIONS = {".locked", ".encrypted", ".crypto", ".enc", ".crypt", ".ransom"}

    def matches(self, event: TelemetryEvent) -> bool:
        target = str(event.target or "")
        return (
            event.syscall_name in ("sys_rename", "sys_unlink", "sys_write")
            and any(target.endswith(ext) for ext in self._EXTENSIONS)
        )

    def explain(self, event: TelemetryEvent) -> str:
        return (
            f"[RANSOM_001] Ransomware encryption activity: file renamed to "
            f"'{event.target}' on {event.pod_name}. "
            f"MITRE T1486: Data Encrypted for Impact."
        )


class _ShellExecutionRule(_Rule):
    """SHELL_001 — Detect unauthorized shell spawn inside a medical container."""
    rule_id = "SHELL_001"
    rule_name = "Unauthorized shell execution in medical container"
    mitre_technique_id = "T1059.004"
    mitre_technique_name = "Command and Scripting Interpreter: Unix Shell"
    confidence = 0.92
    severity = "HIGH"

    _SHELL_BINARIES = {
        "bash", "sh", "zsh", "fish", "tcsh", "csh",
        "/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh",
        "/bin/zsh", "/usr/bin/zsh",
    }
    _SHELL_SUFFIXES = ("/bash", "/sh", "/zsh", "/fish")

    def matches(self, event: TelemetryEvent) -> bool:
        binary = str(event.binary or "")
        return (
            event.syscall_name == "sys_execve"
            and (
                binary in self._SHELL_BINARIES
                or binary.endswith(self._SHELL_SUFFIXES)
                or any(s in binary for s in ("bash", "zsh"))
            )
        )

    def explain(self, event: TelemetryEvent) -> str:
        return (
            f"[SHELL_001] Unauthorized shell spawned in {event.pod_name}: "
            f"binary='{event.binary}'. Medical containers should not spawn shells. "
            f"MITRE T1059.004: Unix Shell."
        )


class _SmbLateralRule(_Rule):
    """LATERAL_001 — Detect SMB connection on port 445 (lateral movement)."""
    rule_id = "LATERAL_001"
    rule_name = "SMB lateral movement attempt (port 445)"
    mitre_technique_id = "T1021.002"
    mitre_technique_name = "Remote Services: SMB/Windows Admin Shares"
    confidence = 0.94
    severity = "HIGH"

    def matches(self, event: TelemetryEvent) -> bool:
        target = str(event.target or "")
        return (
            event.syscall_name in ("sys_connect", "sys_sendto")
            and (event.port == 445 or ":445" in target or "/445" in target)
        )

    def explain(self, event: TelemetryEvent) -> str:
        return (
            f"[LATERAL_001] SMB lateral movement from {event.pod_name} to "
            f"'{event.target}' (port 445). Medical containers have no legitimate "
            f"use for SMB. MITRE T1021.002."
        )


class _ReconRule(_Rule):
    """RECON_001 — Detect port scanning or network service discovery."""
    rule_id = "RECON_001"
    rule_name = "Network reconnaissance / port scan"
    mitre_technique_id = "T1046"
    mitre_technique_name = "Network Service Discovery"
    confidence = 0.88
    severity = "MEDIUM"

    def matches(self, event: TelemetryEvent) -> bool:
        binary = str(event.binary or "").lower()
        target = str(event.target or "").lower()
        params = event.params or {}
        return (
            "nmap" in binary
            or "masscan" in binary
            or "scan" in target
            or params.get("scan") == "recon"
            or params.get("type") == "port_scan"
        )

    def explain(self, event: TelemetryEvent) -> str:
        return (
            f"[RECON_001] Network reconnaissance on {event.pod_name}: "
            f"binary='{event.binary}', target='{event.target}'. "
            f"MITRE T1046: Network Service Discovery."
        )


class _DnsExfilRule(_Rule):
    """EXFIL_001 — Detect DNS tunnelling / exfiltration via port 53."""
    rule_id = "EXFIL_001"
    rule_name = "DNS exfiltration / tunnelling (port 53)"
    mitre_technique_id = "T1071.004"
    mitre_technique_name = "Application Layer Protocol: DNS"
    confidence = 0.87
    severity = "HIGH"

    def matches(self, event: TelemetryEvent) -> bool:
        target = str(event.target or "")
        params = event.params or {}
        return (
            event.syscall_name in ("sys_sendto", "sys_connect")
            and (
                event.port == 53
                or "exfil" in target
                or "tunnel" in target
                or "c2" in target.lower()
                or "exfil" in str(params).lower()
            )
        )

    def explain(self, event: TelemetryEvent) -> str:
        return (
            f"[EXFIL_001] DNS exfiltration from {event.pod_name} to "
            f"'{event.target}' (port {event.port}). "
            f"MITRE T1071.004: Application Layer Protocol DNS."
        )


class _BackdoorRule(_Rule):
    """BACKDOOR_001 — Detect reverse shell / backdoor on known C2 ports."""
    rule_id = "BACKDOOR_001"
    rule_name = "Reverse shell / backdoor C2 connection"
    mitre_technique_id = "T1071"
    mitre_technique_name = "Application Layer Protocol"
    confidence = 0.93
    severity = "CRITICAL"

    _C2_PORTS = {4444, 1337, 8888, 31337, 6666, 9999, 12345}

    def matches(self, event: TelemetryEvent) -> bool:
        target = str(event.target or "")
        return (
            event.syscall_name in ("sys_connect", "sys_sendto")
            and (
                event.port in self._C2_PORTS
                or "attacker" in target
                or "c2" in target.lower()
                or "malware" in target.lower()
            )
        )

    def explain(self, event: TelemetryEvent) -> str:
        return (
            f"[BACKDOOR_001] Reverse shell / C2 connection from {event.pod_name} "
            f"to '{event.target}' (port {event.port}). "
            f"MITRE T1071: Application Layer Protocol."
        )


class _BruteforceRule(_Rule):
    """BRUTE_001 — Detect auth bruteforce (repeated non-200 HTTP responses)."""
    rule_id = "BRUTE_001"
    rule_name = "Authentication bruteforce (repeated failures)"
    mitre_technique_id = "T1110"
    mitre_technique_name = "Brute Force"
    confidence = 0.85
    severity = "HIGH"

    def matches(self, event: TelemetryEvent) -> bool:
        params = event.params or {}
        return (
            params.get("type") == "auth_bruteforce"
            or params.get("attempt_count", 0) >= 5
            or (
                "login" in str(event.target or "").lower()
                and params.get("status") in (401, 403)
                and params.get("consecutive_failures", 0) >= 3
            )
        )

    def explain(self, event: TelemetryEvent) -> str:
        attempts = (event.params or {}).get("attempt_count", "multiple")
        return (
            f"[BRUTE_001] Authentication bruteforce on {event.pod_name}: "
            f"{attempts} consecutive failures against '{event.target}'. "
            f"MITRE T1110: Brute Force."
        )


# ── Rule Engine ──

class RuleEngine:
    """
    Deterministic signature-based detection engine.

    Evaluates all rules against an event and returns the first matching
    RuleMatch, or None if no rules fire. Rules are evaluated in priority order
    (most severe first).

    This is completely separate from the ML detector. Both run in parallel;
    their results are recorded independently in the detection record.
    """

    # Rules in priority order (most critical first)
    _RULES: list[_Rule] = [
        _RansomwareRule(),
        _BackdoorRule(),
        _SmbLateralRule(),
        _ShellExecutionRule(),
        _DnsExfilRule(),
        _ReconRule(),
        _BruteforceRule(),
    ]

    def evaluate(self, event: TelemetryEvent) -> Optional[RuleMatch]:
        """
        Evaluate all rules against an event.
        Returns the first matching RuleMatch (highest priority), or None.
        """
        for rule in self._RULES:
            try:
                if rule.matches(event):
                    match = rule.to_match(event)
                    logger.info(
                        "Rule fired: %s on pod=%s target='%s'",
                        match.rule_id, event.pod_name, event.target
                    )
                    return match
            except Exception as e:
                logger.warning("Rule %s evaluation error: %s", rule.rule_id, e)
        return None

    @property
    def rule_count(self) -> int:
        return len(self._RULES)

    @property
    def rule_summary(self) -> list[dict]:
        """Summary of all rules for the API status endpoint."""
        return [
            {
                "rule_id": r.rule_id,
                "rule_name": r.rule_name,
                "mitre": r.mitre_technique_id,
                "severity": r.severity,
                "confidence": r.confidence,
            }
            for r in self._RULES
        ]


# Singleton
rule_engine = RuleEngine()
