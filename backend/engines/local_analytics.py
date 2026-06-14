"""
Local Analytics Engine
----------------------
Dedicated local analytics module for Trinetra Sentinel.
Performs all security analytics without any external API dependency:

- Log aggregation and grouping
- Event correlation and attack chain detection
- Per-incident risk scoring
- Anomaly detection (statistical outliers)
- Incident timeline construction
- Local report generation (English markdown)

This engine feeds pre-processed analytics to Gemini (when available)
instead of raw logs, reducing API token consumption.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone


# ── Attack chain patterns ──
# Sequences of event types that indicate known attack progression
ATTACK_CHAINS: list[dict] = [
    {
        "name": "Credential Attack -> Execution",
        "pattern": ["failed_login", "suspicious_process"],
        "severity_boost": 20,
        "description": "Failed logins followed by suspicious process execution suggest credential compromise leading to code execution.",
    },
    {
        "name": "Credential Attack -> Persistence",
        "pattern": ["failed_login", "registry_persistence"],
        "severity_boost": 25,
        "description": "Failed logins followed by registry persistence indicate an attacker establishing long-term access after brute force.",
    },
    {
        "name": "Credential Attack -> Privilege Escalation",
        "pattern": ["failed_login", "account_lockout", "dangerous_command"],
        "severity_boost": 30,
        "description": "Brute force followed by account lockout and dangerous commands indicates privilege escalation attempt.",
    },
    {
        "name": "USB -> Malware Execution",
        "pattern": ["usb_threat_detected", "suspicious_process"],
        "severity_boost": 25,
        "description": "USB threat detected followed by suspicious process execution suggests USB-borne malware activation.",
    },
    {
        "name": "USB -> Persistence",
        "pattern": ["usb_threat_detected", "registry_persistence"],
        "severity_boost": 25,
        "description": "USB threat followed by registry persistence indicates malware establishing persistence from removable media.",
    },
    {
        "name": "Execution -> Ransomware",
        "pattern": ["powershell_encoded", "ransomware_activity"],
        "severity_boost": 35,
        "description": "Encoded PowerShell followed by ransomware activity indicates an active ransomware deployment chain.",
    },
    {
        "name": "Execution -> Data Destruction",
        "pattern": ["dangerous_command", "mass_file_deletion"],
        "severity_boost": 30,
        "description": "Dangerous command followed by mass file deletion suggests data destruction attack.",
    },
    {
        "name": "Persistence -> Execution -> Exfiltration",
        "pattern": ["registry_persistence", "suspicious_process", "mass_file_deletion"],
        "severity_boost": 35,
        "description": "Persistence, execution, then file operations indicate a full compromise chain with potential data exfiltration.",
    },
    {
        "name": "AI-Assisted Attack Chain",
        "pattern": ["ai_assisted_command", "dangerous_command"],
        "severity_boost": 15,
        "description": "AI-generated command followed by dangerous execution indicates potentially compromised AI tool or malicious use.",
    },
    {
        "name": "Ransomware -> File Encryption",
        "pattern": ["ransomware_activity", "mass_file_rename"],
        "severity_boost": 30,
        "description": "Ransomware activity with mass file renaming confirms active file encryption attack.",
    },
]


class LocalAnalyticsEngine:
    """Local security analytics engine — no external API dependency.

    Provides comprehensive security analysis by aggregating and correlating
    local system events, generating risk scores, detecting anomalies, and
    producing structured incident reports.
    """

    def __init__(self):
        self._cache: dict | None = None
        self._cache_key: str | None = None
        self._cache_time: float = 0.0
        self._cache_ttl: float = 20.0  # Re-evaluate every 20 seconds

    # ──────────────────────────────────────────────────────────────
    # Log Aggregation
    # ──────────────────────────────────────────────────────────────
    def aggregate_logs(self, events: list[dict]) -> dict:
        """Group events by category, severity, source, and time window.

        Returns a structured summary of event distribution.
        """
        recent = events[:200]
        if not recent:
            return {
                "total_events": 0,
                "by_category": {},
                "by_severity": {},
                "by_source": {},
                "by_event_type": {},
                "time_range_minutes": 0,
                "events_per_minute": 0.0,
            }

        categories = Counter(e.get("category", "unknown") for e in recent)
        severities = Counter(e.get("severity", "low") for e in recent)
        sources = Counter(e.get("source", "unknown") for e in recent)
        event_types = Counter(e.get("event_type", "unknown") for e in recent)

        # Time range
        time_range_minutes = 0
        events_per_minute = 0.0
        try:
            newest = datetime.fromisoformat(recent[0].get("timestamp", "").replace("Z", "+00:00"))
            oldest = datetime.fromisoformat(recent[-1].get("timestamp", "").replace("Z", "+00:00"))
            if newest.tzinfo is None:
                newest = newest.replace(tzinfo=timezone.utc)
            if oldest.tzinfo is None:
                oldest = oldest.replace(tzinfo=timezone.utc)
            time_range_minutes = max(1, int((newest - oldest).total_seconds() / 60))
            events_per_minute = round(len(recent) / time_range_minutes, 2)
        except (ValueError, TypeError):
            pass

        return {
            "total_events": len(recent),
            "by_category": dict(categories.most_common(10)),
            "by_severity": dict(severities),
            "by_source": dict(sources.most_common(10)),
            "by_event_type": dict(event_types.most_common(12)),
            "time_range_minutes": time_range_minutes,
            "events_per_minute": events_per_minute,
        }

    # ──────────────────────────────────────────────────────────────
    # Event Correlation — Attack Chain Detection
    # ──────────────────────────────────────────────────────────────
    def correlate_events(self, events: list[dict]) -> dict:
        """Detect attack chains by looking for known event type sequences.

        Returns detected chains with descriptions and severity boosts.
        """
        recent = events[:120]
        if not recent:
            return {"chains_detected": 0, "chains": [], "max_chain_severity": "low"}

        # Collect event types in chronological order (oldest first)
        sorted_events = sorted(recent, key=lambda e: e.get("timestamp", ""))
        event_type_sequence = [e.get("event_type", "") for e in sorted_events]
        event_type_set = set(event_type_sequence)

        detected_chains = []
        max_severity_score = 0

        for chain in ATTACK_CHAINS:
            pattern = chain["pattern"]
            # Check if all pattern elements exist in the event sequence (in order)
            matched = True
            last_idx = -1
            for p_type in pattern:
                found = False
                for idx in range(last_idx + 1, len(event_type_sequence)):
                    if event_type_sequence[idx] == p_type:
                        last_idx = idx
                        found = True
                        break
                if not found:
                    matched = False
                    break

            if matched:
                detected_chains.append({
                    "name": chain["name"],
                    "description": chain["description"],
                    "pattern": pattern,
                    "severity_boost": chain["severity_boost"],
                    "matched": True,
                })
                max_severity_score = max(max_severity_score, chain["severity_boost"])

        # Determine max chain severity
        if max_severity_score >= 30:
            max_chain_severity = "critical"
        elif max_severity_score >= 20:
            max_chain_severity = "high"
        elif max_severity_score > 0:
            max_chain_severity = "medium"
        else:
            max_chain_severity = "low"

        return {
            "chains_detected": len(detected_chains),
            "chains": detected_chains,
            "max_chain_severity": max_chain_severity,
            "max_chain_score_boost": max_severity_score,
        }

    # ──────────────────────────────────────────────────────────────
    # Per-Incident Risk Scoring
    # ──────────────────────────────────────────────────────────────
    def compute_risk_scores(self, events: list[dict]) -> dict:
        """Compute per-category and per-chain risk scores.

        Returns overall score plus breakdown by category.
        """
        recent = events[:120]
        if not recent:
            return {"overall": 0, "by_category": {}, "by_chain": {}, "high_risk_categories": []}

        # Per-category scores
        category_scores: dict[str, int] = defaultdict(int)
        for e in recent:
            cat = e.get("category", "unknown")
            score = int(e.get("score", 0))
            category_scores[cat] = max(category_scores[cat], score)

        # Identify high-risk categories
        high_risk = [
            {"category": cat, "score": score}
            for cat, score in sorted(category_scores.items(), key=lambda x: x[1], reverse=True)
            if score >= 20
        ]

        # Per-chain scores from correlation
        correlation = self.correlate_events(events)
        chain_scores = [
            {"name": c["name"], "score": c["severity_boost"]}
            for c in correlation.get("chains", [])
        ]

        # Overall score (weighted combination)
        overall = min(100, sum(
            int(e.get("score", 0)) * (
                1.5 if e.get("severity") == "critical" else
                1.2 if e.get("severity") == "high" else
                0.8 if e.get("severity") == "medium" else
                0.3
            )
            for e in recent[:40]
        ))
        overall = min(100, int(overall))

        return {
            "overall": overall,
            "by_category": dict(sorted(category_scores.items(), key=lambda x: x[1], reverse=True)),
            "by_chain": chain_scores,
            "high_risk_categories": high_risk[:6],
        }

    # ──────────────────────────────────────────────────────────────
    # Anomaly Detection
    # ──────────────────────────────────────────────────────────────
    def detect_anomalies(self, events: list[dict], snapshot: dict | None = None) -> dict:
        """Detect statistical anomalies in event frequency and resource usage.

        Returns detected anomalies with descriptions.
        """
        anomalies = []
        recent = events[:120]

        # Event burst detection (>15 events in 10 min window)
        now = datetime.now(timezone.utc)
        window_10m = now - timedelta(minutes=10)
        recent_10m = []
        for e in recent:
            try:
                ts = datetime.fromisoformat(e.get("timestamp", "").replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= window_10m:
                    recent_10m.append(e)
            except (ValueError, TypeError):
                continue

        if len(recent_10m) > 15:
            anomalies.append({
                "type": "event_burst",
                "description": f"Activity burst: {len(recent_10m)} events in last 10 minutes (threshold: 15)",
                "severity": "medium" if len(recent_10m) < 30 else "high",
                "count": len(recent_10m),
            })

        # Severity spike detection
        severities = Counter(e.get("severity", "low") for e in recent)
        high_critical = severities.get("high", 0) + severities.get("critical", 0)
        if high_critical > 5:
            anomalies.append({
                "type": "severity_spike",
                "description": f"High severity spike: {high_critical} high/critical events detected simultaneously",
                "severity": "high",
                "count": high_critical,
            })

        # Resource anomalies from snapshot
        if snapshot:
            cpu = snapshot.get("cpu", 0)
            memory = snapshot.get("memory", 0)
            if cpu > 95:
                anomalies.append({
                    "type": "cpu_anomaly",
                    "description": f"CPU usage critical: {cpu}% (threshold: 95%)",
                    "severity": "high",
                    "value": cpu,
                })
            if memory > 95:
                anomalies.append({
                    "type": "memory_anomaly",
                    "description": f"Memory usage critical: {memory}% (threshold: 95%)",
                    "severity": "high",
                    "value": memory,
                })

        # Event type concentration (single type dominating)
        event_types = Counter(e.get("event_type", "") for e in recent)
        if len(recent) > 10:
            most_common_type, most_common_count = event_types.most_common(1)[0]
            concentration = most_common_count / len(recent)
            if concentration > 0.6 and most_common_count > 10:
                anomalies.append({
                    "type": "event_concentration",
                    "description": f"Event concentration: {most_common_type} accounts for {concentration:.0%} of all events ({most_common_count} of {len(recent)})",
                    "severity": "medium",
                    "count": most_common_count,
                })

        return {
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
        }

    # ──────────────────────────────────────────────────────────────
    # Incident Timeline
    # ──────────────────────────────────────────────────────────────
    def build_incident_timeline(self, events: list[dict]) -> dict:
        """Build a chronological incident timeline from events.

        Returns structured timeline with phases and key events.
        """
        recent = events[:80]
        if not recent:
            return {"events": [], "phases": [], "duration_minutes": 0, "key_events": []}

        sorted_events = sorted(recent, key=lambda e: e.get("timestamp", ""))

        # Build timeline entries
        timeline = []
        key_events = []
        for e in sorted_events[:30]:
            entry = {
                "timestamp": e.get("timestamp", "")[:19],
                "severity": e.get("severity", "low"),
                "event_type": e.get("event_type", "unknown"),
                "title": e.get("title", ""),
                "score": e.get("score", 0),
            }
            timeline.append(entry)

            # Flag high-severity events as key events
            if e.get("severity") in {"high", "critical"}:
                key_events.append(entry)

        # Identify attack phases
        phases = []
        phase_map = {
            "Initial Access": ["failed_login", "account_lockout", "usb_threat_detected", "usb_device"],
            "Execution": ["powershell_encoded", "dangerous_command", "ai_assisted_command", "suspicious_chain", "suspicious_process"],
            "Persistence": ["registry_persistence"],
            "Privilege Escalation": ["account_lockout", "dangerous_command"],
            "Impact": ["ransomware_activity", "mass_file_deletion", "mass_file_rename", "bulk_file_modification"],
            "Defense Evasion": ["mass_file_deletion"],
            "Lateral Movement": ["usb_threat_detected", "intrusion_correlation"],
        }

        event_type_set = set(e.get("event_type", "") for e in sorted_events)
        for phase_name, phase_types in phase_map.items():
            matched = [t for t in phase_types if t in event_type_set]
            if matched:
                phases.append({
                    "phase": phase_name,
                    "matched_events": matched,
                    "active": True,
                })

        # Duration
        duration_minutes = 0
        try:
            first_ts = datetime.fromisoformat(sorted_events[0].get("timestamp", "").replace("Z", "+00:00"))
            last_ts = datetime.fromisoformat(sorted_events[-1].get("timestamp", "").replace("Z", "+00:00"))
            if first_ts.tzinfo is None:
                first_ts = first_ts.replace(tzinfo=timezone.utc)
            if last_ts.tzinfo is None:
                last_ts = last_ts.replace(tzinfo=timezone.utc)
            duration_minutes = max(1, int(abs((last_ts - first_ts).total_seconds()) / 60))
        except (ValueError, TypeError):
            pass

        return {
            "events": timeline,
            "phases": phases,
            "duration_minutes": duration_minutes,
            "key_events": key_events[:8],
            "total_timeline_events": len(timeline),
        }

    # ──────────────────────────────────────────────────────────────
    # Local Report Generation
    # ──────────────────────────────────────────────────────────────
    def generate_report(self, events: list[dict], score: int, processes: list[dict] | None = None) -> dict:
        """Generate a comprehensive local analytics report.

        Purely local — no Gemini dependency. Returns structured report
        with executive summary, timeline, risk assessment, attack chains,
        and recommended actions.
        """
        now = time.monotonic()
        cache_key = f"report-{score}-{len(events)}"
        if self._cache and self._cache_key == cache_key and now - self._cache_time < self._cache_ttl:
            return self._cache

        # Run all analytics components
        aggregation = self.aggregate_logs(events)
        correlation = self.correlate_events(events)
        risk_scores = self.compute_risk_scores(events)
        anomalies = self.detect_anomalies(events)
        timeline = self.build_incident_timeline(events)

        # Generate markdown report
        report_text = self._build_report_text(
            events, score, aggregation, correlation, risk_scores,
            anomalies, timeline, processes or [],
        )

        # Build executive summary (for voice pipeline)
        exec_summary = self._build_executive_summary(
            score, aggregation, correlation, risk_scores, anomalies,
        )

        result = {
            "report": report_text,
            "executive_summary": exec_summary,
            "aggregation": aggregation,
            "correlation": correlation,
            "risk_scores": risk_scores,
            "anomalies": anomalies,
            "timeline": timeline,
            "score": score,
            "provider": "local-analytics",
            "model": "trinetra-algorithm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        self._cache = result
        self._cache_key = cache_key
        self._cache_time = now
        return result

    def _build_report_text(
        self, events, score, aggregation, correlation, risk_scores,
        anomalies, timeline, processes,
    ) -> str:
        """Build the full markdown report text."""
        lines = []

        # Header
        lines.append("# Incident Report — Trinetra Sentinel")
        lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
        lines.append(f"**Risk Score:** {score}/100")
        lines.append(f"**Total Events Analyzed:** {aggregation['total_events']}")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        severity_bd = aggregation.get("by_severity", {})
        high_count = severity_bd.get("high", 0) + severity_bd.get("critical", 0)
        critical_count = severity_bd.get("critical", 0)

        if score >= 80:
            lines.append(f"**CRITICAL**: The system risk score is {score}/100. {high_count} high/critical alerts require immediate investigation. The security posture indicates a potential active compromise.")
        elif score >= 50:
            lines.append(f"**HIGH RISK**: The system risk score is {score}/100. {high_count} high-severity alerts detected. Elevated threat indicators suggest suspicious activity that needs urgent review.")
        elif score >= 20:
            lines.append(f"**WARNING**: The system risk score is {score}/100. Some indicators of concern detected. Continued monitoring recommended.")
        else:
            lines.append(f"**SAFE**: The system risk score is {score}/100. No significant threats detected. System appears to be operating normally.")
        lines.append("")

        # Event Timeline
        lines.append("## Event Timeline")
        if timeline.get("events"):
            lines.append(f"**Duration:** ~{timeline.get('duration_minutes', 0)} minutes")
            lines.append(f"**Key Events:** {len(timeline.get('key_events', []))}")
            for phase in timeline.get("phases", []):
                lines.append(f"- **{phase['phase']}**: {', '.join(phase['matched_events'])}")
            lines.append("")
            for entry in timeline.get("key_events", [])[:8]:
                lines.append(f"- [{entry['severity'].upper()}] {entry['timestamp']} — {entry['title']}")
        else:
            lines.append("No events in timeline.")
        lines.append("")

        # Risk Assessment
        lines.append("## Risk Assessment")
        lines.append(f"- **Overall Risk Score:** {risk_scores.get('overall', score)}/100")
        high_risk_cats = risk_scores.get("high_risk_categories", [])
        if high_risk_cats:
            for cat_info in high_risk_cats[:5]:
                lines.append(f"- **{cat_info['category']}**: score {cat_info['score']}")
        lines.append(f"- **Severity Breakdown:** {dict(aggregation.get('by_severity', {}))}")
        lines.append("")

        # Attack Chain Analysis
        lines.append("## Attack Chain Analysis")
        chains = correlation.get("chains", [])
        if chains:
            lines.append(f"**{len(chains)} attack chain(s) detected:**")
            for chain in chains:
                lines.append(f"- **{chain['name']}** (score boost: +{chain['severity_boost']})")
                lines.append(f"  {chain['description']}")
        else:
            lines.append("No known attack chain patterns detected in current events.")
        lines.append("")

        # Anomalies
        anomaly_list = anomalies.get("anomalies", [])
        if anomaly_list:
            lines.append("## Anomalies Detected")
            for a in anomaly_list:
                lines.append(f"- **{a['type']}** [{a['severity'].upper()}]: {a['description']}")
            lines.append("")

        # Top Processes
        if processes:
            top_procs = sorted(processes, key=lambda p: p.get("cpu", 0), reverse=True)[:5]
            lines.append("## Top Processes by Resource Usage")
            for p in top_procs:
                lines.append(f"- **{p.get('name', 'unknown')}** (PID {p.get('pid', '?')}): CPU {p.get('cpu', 0)}%, RAM {p.get('memory', 0)}%")
            lines.append("")

        # Event Distribution
        lines.append("## Event Distribution")
        by_type = aggregation.get("by_event_type", {})
        if by_type:
            for etype, count in list(by_type.items())[:10]:
                lines.append(f"- {etype.replace('_', ' ').title()}: {count}")
        lines.append("")

        # Recommended Actions
        lines.append("## Recommended Actions")
        if score >= 80:
            lines.append("1. **IMMEDIATE**: Isolate the endpoint from the network")
            lines.append("2. **IMMEDIATE**: Review all critical alerts in the Live Threat Feed")
            lines.append("3. **IMMEDIATE**: Check for active data exfiltration in network connections")
            lines.append("4. Run a full Windows Defender scan on all drives")
            lines.append("5. Review all registry persistence entries and scheduled tasks")
            lines.append("6. Reset all credentials used on this system")
            lines.append("7. File a formal incident report with timeline and findings")
        elif score >= 50:
            lines.append("1. Review all high-severity alerts immediately")
            lines.append("2. Run a full Windows Defender scan")
            lines.append("3. Check active processes for unknown binaries")
            lines.append("4. Review registry Run keys for unauthorized entries")
            lines.append("5. Monitor for recurring patterns over the next 30 minutes")
        elif score >= 20:
            lines.append("1. Review medium-severity alerts in the threat feed")
            lines.append("2. Run a quick Windows Defender scan")
            lines.append("3. Continue monitoring for escalation")
        else:
            lines.append("1. No immediate action required")
            lines.append("2. Continue routine monitoring")
            lines.append("3. Run periodic security scans")
        lines.append("")

        # MITRE ATT&CK context
        lines.append("## MITRE ATT&CK References")
        from ..ai.mitre_mapper import build_mitre_summary
        try:
            mitre = build_mitre_summary(events[:80])
            for t in mitre.get("techniques", [])[:8]:
                lines.append(f"- **{t['technique_id']}** {t['name']} ({t['tactic']})")
        except Exception:
            lines.append("- MITRE mapping unavailable")

        return "\n".join(lines)

    def _build_executive_summary(self, score, aggregation, correlation, risk_scores, anomalies) -> str:
        """Build a concise executive summary suitable for voice delivery."""
        severity_bd = aggregation.get("by_severity", {})
        high_count = severity_bd.get("high", 0) + severity_bd.get("critical", 0)
        total = aggregation.get("total_events", 0)
        chains = correlation.get("chains_detected", 0)
        anomaly_count = anomalies.get("anomalies_detected", 0)

        parts = []

        if score >= 80:
            parts.append(f"Critical security situation. Risk score is {score} out of 100.")
        elif score >= 50:
            parts.append(f"High risk situation. Risk score is {score} out of 100.")
        elif score >= 20:
            parts.append(f"Warning level. Risk score is {score} out of 100.")
        else:
            parts.append(f"System is secure. Risk score is {score} out of 100.")

        parts.append(f"{total} security events analyzed.")

        if high_count > 0:
            parts.append(f"{high_count} high severity alerts require attention.")

        if chains > 0:
            parts.append(f"{chains} attack chain pattern(s) detected.")

        if anomaly_count > 0:
            parts.append(f"{anomaly_count} anomalies found.")

        if score < 20 and high_count == 0:
            parts.append("No significant threats detected. System operating normally.")

        return " ".join(parts)
