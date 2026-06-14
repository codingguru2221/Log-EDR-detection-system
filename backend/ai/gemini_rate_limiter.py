"""
Gemini API Rate Limiter
-----------------------
Controls Gemini API call frequency to minimize credit consumption while
ensuring critical threats always receive AI analysis.

Policy:
  - Startup: Maximum 1 Gemini call per application session
  - Threat Analysis: Maximum 1 call per incident
  - Cooldown: Minimum 10 minutes between non-critical calls
  - Critical/High threats bypass cooldown

Severity gating:
  - INFO / LOW: No Gemini call allowed
  - MEDIUM: Gemini allowed with cooldown
  - HIGH / CRITICAL: Gemini allowed, cooldown bypassed
"""

from __future__ import annotations

import os
import threading
import time


def _get_env(key: str, default: str = "") -> str:
    """Read from os.environ or .env file fallback."""
    value = os.environ.get(key, "")
    if value:
        return value
    env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if "=" in line and not line.startswith("#"):
                    k, _, v = line.partition("=")
                    if k.strip() == key:
                        return v.strip()
    except Exception:
        pass
    return default


class GeminiRateLimiter:
    """Thread-safe rate limiter for Gemini API calls.

    Tracks:
      - Startup call usage (max 1 per session)
      - Last call timestamp (for cooldown enforcement)
      - Per-incident call counts (max 1 per incident)
    """

    # Severity levels that are allowed to call Gemini
    ALLOWED_SEVERITIES = {"medium", "high", "critical"}
    # Severities that bypass cooldown
    COOLDOWN_BYPASS_SEVERITIES = {"high", "critical"}

    def __init__(self):
        self._lock = threading.Lock()
        self._startup_call_used: bool = False
        self._last_call_time: float = 0.0
        self._calls_per_incident: dict[str, int] = {}
        self._cooldown_seconds: float = float(
            _get_env("GEMINI_COOLDOWN_MINUTES", "10")
        ) * 60.0
        self._total_calls: int = 0
        self._blocked_calls: int = 0

    @property
    def total_calls(self) -> int:
        """Total Gemini API calls made this session."""
        with self._lock:
            return self._total_calls

    @property
    def blocked_calls(self) -> int:
        """Total calls blocked by rate limiter this session."""
        with self._lock:
            return self._blocked_calls

    @property
    def cooldown_seconds(self) -> float:
        """Cooldown period in seconds."""
        return self._cooldown_seconds

    def allow_startup_call(self) -> bool:
        """Check if a startup summary call is allowed.

        Returns True if no startup call has been made this session.
        Marks the startup call as used if allowed.
        """
        with self._lock:
            if self._startup_call_used:
                self._blocked_calls += 1
                return False
            self._startup_call_used = True
            self._last_call_time = time.monotonic()
            self._total_calls += 1
            return True

    def allow_threat_call(self, severity: str, incident_id: str | None = None) -> bool:
        """Check if a threat analysis call is allowed.

        Args:
            severity: The threat severity ("info", "low", "medium", "high", "critical")
            incident_id: Optional incident identifier for per-incident limiting

        Returns:
            True if the call is allowed, False otherwise.
        """
        severity_lower = (severity or "low").lower().strip()

        with self._lock:
            # Gate 1: Severity check — only medium+ allowed
            if severity_lower not in self.ALLOWED_SEVERITIES:
                self._blocked_calls += 1
                return False

            # Gate 2: Per-incident limit — max 1 call per incident
            if incident_id:
                incident_calls = self._calls_per_incident.get(incident_id, 0)
                if incident_calls >= 1:
                    self._blocked_calls += 1
                    return False

            # Gate 3: Cooldown check (bypassed for high/critical)
            if severity_lower not in self.COOLDOWN_BYPASS_SEVERITIES:
                elapsed = time.monotonic() - self._last_call_time
                if elapsed < self._cooldown_seconds:
                    self._blocked_calls += 1
                    return False

            # All gates passed — allow the call
            self._last_call_time = time.monotonic()
            self._total_calls += 1
            if incident_id:
                self._calls_per_incident[incident_id] = (
                    self._calls_per_incident.get(incident_id, 0) + 1
                )
            return True

    def get_cooldown_remaining(self) -> float:
        """Get seconds remaining until next non-critical call is allowed.

        Returns 0 if no cooldown is active.
        """
        with self._lock:
            if self._last_call_time == 0:
                return 0.0
            elapsed = time.monotonic() - self._last_call_time
            remaining = max(0.0, self._cooldown_seconds - elapsed)
            return remaining

    def is_startup_used(self) -> bool:
        """Check if the startup call has been used."""
        with self._lock:
            return self._startup_call_used

    def get_stats(self) -> dict:
        """Return current rate limiter statistics."""
        with self._lock:
            return {
                "startup_call_used": self._startup_call_used,
                "total_calls": self._total_calls,
                "blocked_calls": self._blocked_calls,
                "cooldown_remaining_seconds": round(
                    max(0.0, self._cooldown_seconds - (time.monotonic() - self._last_call_time))
                    if self._last_call_time > 0
                    else 0.0,
                    1,
                ),
                "cooldown_minutes": self._cooldown_seconds / 60.0,
                "incidents_tracked": len(self._calls_per_incident),
            }

    def severity_allowed(self, severity: str) -> bool:
        """Quick check if a severity level is eligible for Gemini calls."""
        return (severity or "low").lower().strip() in self.ALLOWED_SEVERITIES

    def score_to_severity(self, score: int) -> str:
        """Convert a numeric risk score to a severity string for rate limiting."""
        if score >= 80:
            return "critical"
        if score >= 50:
            return "high"
        if score >= 20:
            return "medium"
        if score > 0:
            return "low"
        return "info"
