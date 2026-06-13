import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .risk import posture_for, severity_for


class AIAnalysisModule:
    """Local algorithm-based analysis engine — no external API needed."""

    def __init__(self):
        self.cache_ttl = 15.0  # Re-evaluate every 15 seconds (was 30)
        self._cache = None
        self._cache_key = None
        self._cache_time = 0.0
        self._last_score = -1
        self._eval_count = 0
        self._last_eval_time = None

    # ──────────────────────────────────────────────────────────────
    # Main summary — replaces Gemini with local algorithm
    # ──────────────────────────────────────────────────────────────
    def summarize(
        self,
        events: list[dict],
        score: int,
        processes: list[dict] | None = None,
        snapshot: dict | None = None,
        logs: list[dict] | None = None,
        force: bool = False,
    ) -> dict:
        now = time.monotonic()
        # Force re-eval if risk score changed significantly (>=10 points)
        score_changed = abs(score - self._last_score) >= 10
        cache_expired = now - self._cache_time >= self.cache_ttl

        if self._cache and not force and not score_changed and not cache_expired:
            return self._cache

        result = self._compute_analysis(events, score, processes or [], snapshot or {}, logs or [])
        result["eval_count"] = self._eval_count + 1
        result["last_eval"] = datetime.now(timezone.utc).isoformat()
        result["score_at_eval"] = score
        self._cache = result
        self._cache_time = now
        self._last_score = score
        self._eval_count += 1
        self._last_eval_time = result["last_eval"]
        return result

    # ──────────────────────────────────────────────────────────────
    # Answer user questions with data-driven logic
    # ──────────────────────────────────────────────────────────────
    def answer_question(
        self,
        question: str,
        events: list[dict],
        score: int,
        processes: list[dict] | None = None,
        snapshot: dict | None = None,
        logs: list[dict] | None = None,
    ) -> dict:
        question = question.strip().lower()[:800]
        if not question:
            return {"answer": "Please enter a question.", "provider": "local", "mode": "local_analysis"}

        events = events or []
        processes = processes or []
        snapshot = snapshot or {}

        # Route question to the right analysis function
        if any(kw in question for kw in ("process", "cpu", "memory", "ram", "resource")):
            return {"answer": self._answer_processes(processes, events), "provider": "local", "mode": "local_analysis"}
        if any(kw in question for kw in ("risk", "threat", "danger", "safe", "secure", "score")):
            return {"answer": self._answer_risk(events, score), "provider": "local", "mode": "local_analysis"}
        if any(kw in question for kw in ("usb", "device", "storage", "external", "drive")):
            return {"answer": self._answer_usb(events), "provider": "local", "mode": "local_analysis"}
        if any(kw in question for kw in ("ai", "copilot", "cursor", "claude", "attribution", "coding")):
            return {"answer": self._answer_ai_attribution(events), "provider": "local", "mode": "local_analysis"}
        if any(kw in question for kw in ("file", "delet", "modif", "change", "rename", "code protect")):
            return {"answer": self._answer_file_activity(events), "provider": "local", "mode": "local_analysis"}
        if any(kw in question for kw in ("log", "event", "windows", "system log", "application log")):
            return {"answer": self._answer_logs(logs or []), "provider": "local", "mode": "local_analysis"}
        if any(kw in question for kw in ("summary", "overview", "status", "what", "tell", "report")):
            analysis = self._compute_analysis(events, score, processes, snapshot, logs or [])
            return {"answer": self._answer_overview(analysis), "provider": "local", "mode": "local_analysis"}

        # Default: general context answer
        return {"answer": self._answer_general(question, events, score, processes), "provider": "local", "mode": "local_analysis"}

    # ──────────────────────────────────────────────────────────────
    # Core analysis algorithm
    # ──────────────────────────────────────────────────────────────
    def _compute_analysis(self, events, score, processes, snapshot, logs) -> dict:
        recent = events[:120]
        categories = Counter(e.get("category", "unknown") for e in recent)
        severities = Counter(e.get("severity", "low") for e in recent)
        event_types = Counter(e.get("event_type", "unknown") for e in recent)

        # Categorize events
        usb_events = [e for e in recent if e.get("source") == "usb-monitor" or e.get("category") == "usb-security"]
        ai_events = [e for e in recent if e.get("metadata", {}).get("ai_attribution")]
        high_events = [e for e in recent if e.get("severity") in {"high", "critical"}]
        critical_events = [e for e in recent if e.get("severity") == "critical"]
        file_events = [e for e in recent if e.get("event_type") in {
            "mass_file_deletion", "mass_file_rename", "bulk_file_modification", "ai_bulk_file_change"
        }]
        threat_events = [e for e in recent if e.get("event_type") in {
            "suspicious_process", "suspicious_chain", "powershell_encoded",
            "dangerous_command", "malware_signature", "ransomware_activity",
            "intrusion_correlation", "threat_detected", "registry_persistence",
        }]
        resource_events = [e for e in recent if e.get("event_type") in {
            "high_cpu_usage", "high_memory_usage", "anomaly",
        }]

        # Build findings
        findings = self._build_findings(
            usb_events, ai_events, high_events, critical_events,
            file_events, threat_events, resource_events, events, score,
        )

        # Build recommendations
        recommendations = self._build_recommendations(
            usb_events, ai_events, high_events, file_events,
            threat_events, resource_events, score, processes,
        )

        # Build threat summary
        threat_summary = self._build_threat_summary(
            recent, score, high_events, critical_events, threat_events,
        )

        # Confidence level
        confidence = "high" if len(recent) > 20 else ("medium" if len(recent) > 5 else "low")

        return {
            "mode": "local_analysis",
            "system_access": False,
            "overall_risk": posture_for(score),
            "summary": findings,
            "top_categories": categories.most_common(6),
            "severity_breakdown": dict(severities),
            "event_type_breakdown": dict(event_types.most_common(8)),
            "recommendations": recommendations,
            "threat_summary": threat_summary,
            "confidence": confidence,
            "provider": "local",
            "model": "trinetra-algorithm",
            "error": None,
        }

    # ──────────────────────────────────────────────────────────────
    # Findings generator
    # ──────────────────────────────────────────────────────────────
    def _build_findings(self, usb_events, ai_events, high_events, critical_events,
                        file_events, threat_events, resource_events, all_events, score) -> list[str]:
        findings = []

        # Temporal burst detection
        recent_10min = self._events_in_window(all_events, minutes=10)
        if len(recent_10min) > 15:
            findings.append(f"**Activity burst detected:** {len(recent_10min)} events in the last 10 minutes — elevated system activity.")

        # Critical events
        if critical_events:
            types = Counter(e.get("event_type", "unknown") for e in critical_events)
            details = ", ".join(f"{t} ({c})" for t, c in types.most_common(3))
            findings.append(f"**{len(critical_events)} critical event(s):** {details}. Immediate review recommended.")

        # High severity
        if high_events and not critical_events:
            types = Counter(e.get("event_type", "unknown") for e in high_events)
            details = ", ".join(f"{t} ({c})" for t, c in types.most_common(3))
            findings.append(f"**{len(high_events)} high severity event(s):** {details}.")

        # USB activity
        if usb_events:
            devices = set()
            for e in usb_events:
                meta = e.get("metadata", {})
                dev = meta.get("device_id") or meta.get("name") or meta.get("label")
                if dev:
                    devices.add(str(dev))
            device_info = f" Device(s): {', '.join(list(devices)[:3])}" if devices else ""
            findings.append(f"**{len(usb_events)} USB event(s):** External storage activity detected.{device_info}")

        # AI attribution
        if ai_events:
            tools = Counter()
            for e in ai_events:
                tool = e.get("metadata", {}).get("ai_tool") or "unknown"
                tools[tool] += 1
            tool_info = ", ".join(f"{t} ({c})" for t, c in tools.most_common(4))
            findings.append(f"**{len(ai_events)} AI-attributed event(s):** Activity linked to AI tools — {tool_info}.")

        # File system threats
        if file_events:
            findings.append(f"**{len(file_events)} file system alert(s):** Bulk file operations detected (deletion, rename, or modification).")

        # Intrusion/threat patterns
        if threat_events:
            types = Counter(e.get("event_type", "unknown") for e in threat_events)
            details = ", ".join(f"{t.replace('_', ' ')} ({c})" for t, c in types.most_common(3))
            findings.append(f"**{len(threat_events)} threat indicator(s):** {details}.")

        # Resource anomalies
        if resource_events:
            findings.append(f"**{len(resource_events)} resource anomaly(ies):** Unusual CPU/memory usage patterns observed.")

        # Score context
        if score >= 50:
            findings.append(f"**Risk score is {score}/100** — combined threat indicators are elevated.")
        elif score > 0:
            findings.append(f"**Risk score is {score}/100** — low-level indicators present, no immediate threat.")

        if not findings:
            findings.append("System is operating normally. No threat chains or anomalies detected in recent telemetry.")

        return findings

    # ──────────────────────────────────────────────────────────────
    # Dynamic recommendation engine
    # ──────────────────────────────────────────────────────────────
    def _build_recommendations(self, usb_events, ai_events, high_events,
                               file_events, threat_events, resource_events,
                               score, processes) -> list[str]:
        recs = []

        if critical_or_high := (len(high_events) > 0):
            recs.append("Review all high-risk alerts before allowing further file or shell activity.")

        if usb_events:
            suspicious_usb = [e for e in usb_events if e.get("severity") in {"high", "critical", "medium"}]
            if suspicious_usb:
                recs.append("Scan external storage device before opening any executable or script files.")
            else:
                recs.append("USB device detected — verify device authenticity before transferring sensitive files.")

        if ai_events:
            destructive_ai = [e for e in ai_events if e.get("severity") in {"high", "critical"}]
            if destructive_ai:
                recs.append("AI tool generated high-risk commands — review and approve each action manually.")
            else:
                recs.append("AI coding tools are active — keep them in approval mode for destructive commands.")

        if file_events:
            recs.append("Bulk file operations detected — verify no important files were deleted or modified unintentionally.")

        if threat_events:
            recs.append("Threat indicators found — check process chains and registry persistence entries.")

        if resource_events:
            top_cpu = sorted(processes, key=lambda p: p.get("cpu", 0), reverse=True)[:3]
            names = ", ".join(p.get("name", "?") for p in top_cpu) if top_cpu else "unknown processes"
            recs.append(f"Resource anomalies detected — top consumers: {names}.")

        if score >= 50:
            recs.append("Consider isolating this endpoint if risk score remains above 50 after review.")

        if not recs:
            recs.append("No immediate action required. Continue monitoring.")
            recs.append("Run periodic USB scans and review new process activity.")

        return recs[:5]

    # ──────────────────────────────────────────────────────────────
    # Threat summary
    # ──────────────────────────────────────────────────────────────
    def _build_threat_summary(self, events, score, high_events, critical_events, threat_events) -> str:
        parts = []

        total = len(events)
        if total == 0:
            return "No events to analyze. System telemetry is clean."

        time_range = ""
        if events:
            try:
                oldest = datetime.fromisoformat(events[-1].get("timestamp", "").replace("Z", "+00:00"))
                newest = datetime.fromisoformat(events[0].get("timestamp", "").replace("Z", "+00:00"))
                delta = newest - oldest
                if delta.total_seconds() > 3600:
                    time_range = f"over ~{int(delta.total_seconds() / 3600)}h"
                elif delta.total_seconds() > 60:
                    time_range = f"over ~{int(delta.total_seconds() / 60)}m"
                else:
                    time_range = "in recent activity"
            except (ValueError, TypeError):
                time_range = "in recent activity"

        parts.append(f"Analyzed {total} event(s) {time_range}.")

        if critical_events:
            parts.append(f"{len(critical_events)} critical and {len(high_events)} high-severity alerts require immediate attention.")
        elif high_events:
            parts.append(f"{len(high_events)} high-severity alerts need review.")

        if threat_events:
            correlation_count = sum(1 for e in threat_events if e.get("event_type") == "intrusion_correlation")
            if correlation_count:
                parts.append(f"{correlation_count} correlated intrusion pattern(s) detected across multiple detection engines.")

        parts.append(f"Overall risk posture: **{posture_for(score)}** (score {score}/100).")
        return " ".join(parts)

    # ──────────────────────────────────────────────────────────────
    # Question answering helpers
    # ──────────────────────────────────────────────────────────────
    def _answer_processes(self, processes, events) -> str:
        if not processes:
            return "No active process snapshot available. Wait for the next telemetry refresh."
        top = sorted(processes, key=lambda p: p.get("cpu", 0) + p.get("memory", 0), reverse=True)[:5]
        lines = [f"**Top {len(top)} processes by resource usage:**"]
        for p in top:
            name = p.get("name", "unknown")
            pid = p.get("pid", "?")
            cpu = p.get("cpu", 0)
            mem = p.get("memory", 0)
            status = p.get("status", "?")
            lines.append(f"- **{name}** (PID {pid}): CPU {cpu}%, RAM {mem}%, Status: {status}")

        # Check for resource alerts
        resource_alerts = [e for e in events[:50] if e.get("event_type") in {"high_cpu_usage", "high_memory_usage", "anomaly"}]
        if resource_alerts:
            lines.append(f"\n{len(resource_alerts)} resource anomaly alert(s) in recent telemetry.")

        return "\n".join(lines)

    def _answer_risk(self, events, score) -> str:
        posture = posture_for(score)
        recent = events[:80]
        high = [e for e in recent if e.get("severity") in {"high", "critical"}]
        medium = [e for e in recent if e.get("severity") == "medium"]
        low = [e for e in recent if e.get("severity") == "low"]

        lines = [
            f"**Risk Score:** {score}/100 — **{posture}**",
            f"\n**Event breakdown:** {len(high)} high/critical, {len(medium)} medium, {len(low)} low severity.",
        ]
        if high:
            types = Counter(e.get("event_type", "unknown") for e in high)
            details = ", ".join(f"{t} ({c})" for t, c in types.most_common(5))
            lines.append(f"\n**High-risk events:** {details}")
        if score >= 50:
            lines.append("\nAction required: Review high-risk alerts and consider isolating this endpoint.")
        else:
            lines.append("\nNo immediate action required. Continue monitoring.")
        return "\n".join(lines)

    def _answer_usb(self, events) -> str:
        usb = [e for e in events[:120] if e.get("source") == "usb-monitor" or e.get("category") == "usb-security"]
        if not usb:
            return "No USB device activity detected in recent telemetry."

        devices = set()
        scan_results = []
        for e in usb:
            meta = e.get("metadata", {})
            dev = meta.get("device_id") or meta.get("name") or meta.get("label")
            if dev:
                devices.add(str(dev))
            if e.get("event_type") in {"usb_scan_clean", "usb_scan_suspicious", "usb_threat_detected"}:
                scan_results.append(f"- {e.get('title', 'USB scan')} ({e.get('event_type')})")

        lines = [f"**USB Activity:** {len(usb)} event(s) from {len(devices)} device(s)."]
        if devices:
            lines.append(f"**Devices:** {', '.join(list(devices)[:5])}")
        if scan_results:
            lines.append(f"\n**Scan results:**\n" + "\n".join(scan_results[:5]))
        suspicious = [e for e in usb if e.get("severity") in {"high", "critical"}]
        if suspicious:
            lines.append(f"\n**{len(suspicious)} suspicious USB event(s) detected — scan recommended.**")
        return "\n".join(lines)

    def _answer_ai_attribution(self, events) -> str:
        ai = [e for e in events[:120] if e.get("metadata", {}).get("ai_attribution")]
        if not ai:
            return "No AI-attributed activity detected. AI coding tools are either inactive or not detected."

        tools = Counter()
        for e in ai:
            tool = e.get("metadata", {}).get("ai_tool") or "unknown"
            tools[tool] += 1

        lines = [f"**AI Attribution:** {len(ai)} event(s) linked to AI coding tools."]
        lines.append("**Active tools:**")
        for tool, count in tools.most_common(6):
            lines.append(f"- **{tool}**: {count} event(s)")

        high_ai = [e for e in ai if e.get("severity") in {"high", "critical"}]
        if high_ai:
            lines.append(f"\n**{len(high_ai)} high-risk AI event(s)** — review commands before approving.")
        return "\n".join(lines)

    def _answer_file_activity(self, events) -> str:
        file_evts = [e for e in events[:120] if e.get("event_type") in {
            "mass_file_deletion", "mass_file_rename", "bulk_file_modification", "ai_bulk_file_change"
        }]
        if not file_evts:
            return "No bulk file activity detected. Code protection engine has not flagged any file operations."

        lines = [f"**File Activity:** {len(file_evts)} alert(s) detected."]
        for e in file_evts[:5]:
            lines.append(f"- **{e.get('title', 'File event')}** ({e.get('event_type')}) — {e.get('summary', '')[:100]}")

        lines.append("\nVerify that no important files were deleted or modified unintentionally.")
        return "\n".join(lines)

    def _answer_logs(self, logs) -> str:
        if not logs:
            return "No Windows event logs available. The log collector may not have scanned yet."

        sources = Counter(log.get("source", "unknown") for log in logs)
        levels = Counter(log.get("level", "info") for log in logs)
        lines = [
            f"**Log Analysis:** {len(logs)} log entry(ies) collected.",
            f"**Sources:** {', '.join(f'{s} ({c})' for s, c in sources.most_common(5))}",
            f"**Levels:** {', '.join(f'{l} ({c})' for l, c in levels.most_common(4))}",
        ]
        errors = [log for log in logs if log.get("level") in {"error", "critical"}]
        if errors:
            lines.append(f"\n**{len(errors)} error/critical log(s):**")
            for log in errors[:3]:
                lines.append(f"- {log.get('message', log.get('summary', 'Unknown'))[:120]}")
        return "\n".join(lines)

    def _answer_overview(self, analysis) -> str:
        risk = analysis.get("overall_risk", "Safe")
        summary = analysis.get("summary", [])
        recs = analysis.get("recommendations", [])

        lines = [f"**Overall Status: {risk}**\n"]
        if summary:
            lines.append("**Key Findings:**")
            for s in summary[:4]:
                lines.append(f"- {s}")
        if recs:
            lines.append("\n**Recommendations:**")
            for r in recs[:3]:
                lines.append(f"- {r}")
        return "\n".join(lines)

    def _answer_general(self, question, events, score, processes) -> str:
        recent = events[:60]
        high = [e for e in recent if e.get("severity") in {"high", "critical"}]
        top_procs = sorted(processes, key=lambda p: p.get("cpu", 0), reverse=True)[:3]
        proc_text = ", ".join(f"{p.get('name')} ({p.get('cpu', 0)}% CPU)" for p in top_procs) or "no snapshot"

        return (
            f"**Current telemetry snapshot:**\n"
            f"- Risk: **{posture_for(score)}** ({score}/100)\n"
            f"- Recent events: {len(recent)} total, {len(high)} high/critical\n"
            f"- Top processes: {proc_text}\n\n"
            f"Try asking about: *risk*, *processes*, *USB*, *AI attribution*, *file activity*, or *logs* for detailed analysis."
        )

    # ──────────────────────────────────────────────────────────────
    # Utility
    # ──────────────────────────────────────────────────────────────
    @staticmethod
    def _events_in_window(events: list[dict], minutes: int) -> list[dict]:
        cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
        result = []
        for e in events:
            try:
                ts = datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    result.append(e)
            except (ValueError, TypeError):
                continue
        return result
