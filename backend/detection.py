from collections import deque
from datetime import datetime, timedelta, timezone
import time

from .engines.ai_attribution import AIAttributionEngine
from .engines.risk import EVENT_SCORES as SCORES
from .engines.risk import compute_risk_score, severity_for

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    np = None
    IsolationForest = None


class AnomalyDetector:
    """Small offline model trained on recent local resource samples."""

    def __init__(self):
        self.samples = deque(maxlen=120)
        self.model = IsolationForest(contamination=0.08, random_state=7) if IsolationForest else None
        self.last_fit = 0.0
        self.fit_interval = 30.0
        self.model_ready = False

    def observe(self, snapshot: dict) -> bool:
        sample = [
            snapshot["cpu"],
            snapshot["memory"],
            snapshot["processes"],
            snapshot["connections"],
        ]
        self.samples.append(sample)
        if self.model is None or len(self.samples) < 24:
            return snapshot["cpu"] > 97 or snapshot["memory"] > 98
        try:
            now = time.monotonic()
            if not self.model_ready or now - self.last_fit >= self.fit_interval:
                data = np.array(self.samples)
                self.model.fit(data)
                self.last_fit = now
                self.model_ready = True
            return bool(self.model.predict(np.array([sample]))[0] == -1)
        except Exception:
            self.model_ready = False
            return snapshot["cpu"] > 97 or snapshot["memory"] > 98


class ThreatEngine:
    def __init__(self):
        self.anomaly_detector = AnomalyDetector()
        self.ai_attribution = AIAttributionEngine()
        self.recent_events = deque(maxlen=100)
        self.last_correlation = None

    def create_event(
        self,
        event_type: str,
        title: str,
        summary: str,
        category: str,
        source: str = "local-monitor",
        metadata: dict | None = None,
        timestamp: str | None = None,
    ) -> dict:
        score = SCORES.get(event_type, 0)
        severity = "critical" if event_type == "ransomware_activity" else severity_for(score)
        return {
            "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
            "category": category,
            "event_type": event_type,
            "source": source,
            "severity": severity,
            "score": score,
            "title": title,
            "summary": summary,
            "metadata": metadata or {},
        }

    def correlate(self, event: dict) -> dict | None:
        if event["event_type"] == "intrusion_correlation":
            return None
        now = datetime.now(timezone.utc)
        self.recent_events.append((now, event))
        cutoff = now - timedelta(minutes=5)
        while self.recent_events and self.recent_events[0][0] < cutoff:
            self.recent_events.popleft()

        categories = {item["category"] for _, item in self.recent_events if item["score"] > 0}
        if len(categories) < 3:
            return None
        if self.last_correlation and now - self.last_correlation < timedelta(minutes=3):
            return None

        self.last_correlation = now
        names = ", ".join(sorted(categories))
        return self.create_event(
            "intrusion_correlation",
            "Correlated intrusion pattern",
            f"Multiple suspicious behaviors were correlated across {names}. Review the incident chain immediately.",
            "correlation",
            source="correlation-engine",
            metadata={"categories": sorted(categories)},
        )

    def inspect_process(self, process: dict) -> dict | None:
        name = (process.get("name") or "").lower()
        command = (process.get("cmdline") or "").lower()
        cpu = process.get("cpu", 0)
        memory = process.get("memory", 0)

        dangerous = self.ai_attribution.inspect_command(process)
        if dangerous:
            event_type = "ai_assisted_command" if dangerous["ai_assisted"] else "dangerous_command"
            return self.create_event(
                event_type,
                "Dangerous command observed",
                f"{dangerous['matched_command']} was seen from {dangerous['origin']} with {dangerous['confidence']}% confidence.",
                "ai-attribution" if dangerous["ai_assisted"] else "command",
                source="ai-attribution-engine" if dangerous["ai_assisted"] else "command-auditor",
                metadata={**process, "ai_attribution": dangerous},
            )

        if "powershell" in name and any(flag in command for flag in ("-enc", "-encodedcommand", "frombase64", "-windowstyle hidden", "-w hidden")):
            return self.create_event(
                "powershell_encoded",
                "Encoded PowerShell execution",
                "An encoded PowerShell command was observed. This technique can hide malicious script behavior.",
                "process",
                metadata=process,
            )

        attribution = self.ai_attribution.inspect_process(process)
        if attribution and any(shell in name for shell in ("powershell", "cmd.exe", "pwsh", "bash", "git")):
            return self.create_event(
                "suspicious_chain",
                "AI-origin shell process detected",
                f"{process.get('name', 'Shell')} appears to originate from {attribution.origin} with {attribution.confidence}% confidence.",
                "ai-attribution",
                source="ai-attribution-engine",
                metadata={**process, "ai_attribution": attribution.__dict__},
            )

        if cpu > 90:
            return self.create_event(
                "high_cpu_usage",
                "High CPU usage",
                f"{process.get('name', 'Unknown process')} is consuming more than 90% CPU.",
                "resource",
                metadata=process,
            )

        if memory > 80:
            return self.create_event(
                "high_memory_usage",
                "High memory usage",
                f"{process.get('name', 'Unknown process')} is consuming more than 80% RAM.",
                "resource",
                metadata=process,
            )

        if cpu > 88 or memory > 55:
            return self.create_event(
                "suspicious_process",
                "Abnormal process resource usage",
                f"{process.get('name', 'Unknown process')} is consuming unusually high system resources.",
                "process",
                metadata=process,
            )
        return None

    def inspect_snapshot(self, snapshot: dict) -> dict | None:
        if not self.anomaly_detector.observe(snapshot):
            return None
        return self.create_event(
            "anomaly",
            "Behavioral anomaly detected",
            "Local activity differs from the recent baseline. Review resource usage and active processes.",
            "behavior",
            metadata=snapshot,
        )
