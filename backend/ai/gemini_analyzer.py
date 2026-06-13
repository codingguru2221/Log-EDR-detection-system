"""
Gemini-Powered Threat Intelligence Module
------------------------------------------
Uses Google Gemini API to provide:
1. Threat summarization (human-readable explanations)
2. MITRE ATT&CK inference
3. Explainable alerts ("Why was this alert generated?")
4. AI incident report generation

Falls back gracefully if API key is missing or network is unavailable.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from datetime import datetime, timezone

from .mitre_mapper import build_mitre_summary, map_events_to_mitre


# ── Gemini SDK import (graceful fallback) ──
try:
    import google.generativeai as genai
    _HAS_GENAI = True
except ImportError:
    genai = None
    _HAS_GENAI = False


def _get_env(key: str, default: str = "") -> str:
    """Read from os.environ or .env file fallback."""
    value = os.environ.get(key, "")
    if value:
        return value
    # Try reading .env from project root
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


class GeminiThreatAnalyzer:
    """Gemini-powered threat intelligence — read-only, no system control."""

    def __init__(self):
        self._api_key = _get_env("GEMINI_API_KEY")
        self._model_name = _get_env("GEMINI_MODEL", "gemini-2.5-flash")
        self._timeout = int(_get_env("GEMINI_TIMEOUT_SECONDS", "12"))
        self._cache_ttl = int(_get_env("TRINETRA_AI_CACHE_SECONDS", "45"))
        self._model = None
        self._available = False
        self._cache: dict = {}
        self._cache_time: float = 0.0

        if _HAS_GENAI and self._api_key:
            try:
                genai.configure(api_key=self._api_key)
                self._model = genai.GenerativeModel(self._model_name)
                self._available = True
            except Exception:
                self._available = False

    @property
    def available(self) -> bool:
        return self._available

    def _safe_generate(self, prompt: str, max_tokens: int = 2048) -> str | None:
        """Call Gemini with timeout and error handling."""
        if not self._model:
            return None
        try:
            response = self._model.generate_content(
                prompt,
                generation_config=genai.GenerationConfig(
                    max_output_tokens=max_tokens,
                    temperature=0.3,
                ),
            )
            return response.text
        except Exception:
            return None

    # ──────────────────────────────────────────────────────────────
    # 1. Threat Summarization
    # ──────────────────────────────────────────────────────────────
    def analyze_threat(self, events: list[dict], score: int) -> dict:
        """Generate Gemini-powered threat analysis with MITRE mapping."""
        cache_key = f"threat-{score}-{len(events)}"
        if self._is_cached(cache_key):
            return self._cache[cache_key]

        mitre = build_mitre_summary(events)
        event_summaries = self._summarize_events(events)

        if not self._available:
            result = self._fallback_threat_analysis(events, score, mitre)
            return self._store_cache(cache_key, result)

        prompt = f"""You are Trinetra Sentinel AI, a cybersecurity threat analyst.
Analyze the following endpoint security data and provide a structured threat assessment.

CURRENT RISK SCORE: {score}/100

DETECTED EVENTS ({len(events)} total):
{event_summaries}

MITRE ATT&CK MAPPINGS:
{json.dumps(mitre.get('techniques', [])[:12], indent=2)}

ACTIVE TACTICS: {', '.join(mitre.get('active_tactics', []))}

Provide your analysis in this EXACT format (use markdown):

## Executive Summary
(2-3 sentences about the overall security posture)

## Technical Analysis
(Bullet points for each major threat category detected)

## Potential Impact
(What could happen if these threats are not addressed)

## MITRE ATT&CK Coverage
(List the top 5-8 mapped techniques with their IDs)

## Recommended Actions
(5 prioritized action items)
"""
        text = self._safe_generate(prompt)
        if not text:
            result = self._fallback_threat_analysis(events, score, mitre)
            return self._store_cache(cache_key, result)

        result = {
            "analysis": text,
            "mitre": mitre,
            "score": score,
            "event_count": len(events),
            "provider": "gemini",
            "model": self._model_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }
        return self._store_cache(cache_key, result)

    # ──────────────────────────────────────────────────────────────
    # 2. Explainable Alerts
    # ──────────────────────────────────────────────────────────────
    def explain_alert(self, alert: dict, all_events: list[dict]) -> dict:
        """Explain why a specific alert was generated."""
        if not self._available:
            return self._fallback_explain(alert, all_events)

        # Find related events
        event_type = alert.get("event_type", "")
        related = [e for e in all_events if e.get("event_type") == event_type][:10]
        mitre_techniques = map_events_to_mitre([alert])

        prompt = f"""You are Trinetra Sentinel AI explaining a security alert to a user.

ALERT DETAILS:
- Title: {alert.get('title', 'Unknown')}
- Type: {event_type}
- Severity: {alert.get('severity', 'unknown')}
- Score: {alert.get('score', 0)}/100
- Category: {alert.get('category', 'unknown')}
- Summary: {alert.get('summary', 'No details')}
- Source: {alert.get('source', 'unknown')}

RELATED EVENTS ({len(related)}):
{json.dumps([{{'type': e.get('event_type'), 'title': e.get('title'), 'severity': e.get('severity'), 'time': e.get('timestamp', '')[:19]}} for e in related[:6]], indent=2)}

MITRE ATT&CK MAPPING:
{json.dumps(mitre_techniques[:4], indent=2)}

Explain in simple, clear language:
1. **What happened?** - Plain language description
2. **Why was this alert generated?** - Which events and behaviors triggered it
3. **Why is the severity {alert.get('severity', 'unknown')}?** - Explain the severity level
4. **MITRE ATT&CK Context** - Relevant attack techniques
5. **What should you do?** - Immediate next steps

Keep it under 400 words. Use markdown formatting."""

        text = self._safe_generate(prompt, max_tokens=1024)
        if not text:
            return self._fallback_explain(alert, all_events)

        return {
            "explanation": text,
            "alert_type": event_type,
            "mitre": mitre_techniques,
            "related_events": len(related),
            "provider": "gemini",
            "model": self._model_name,
        }

    # ──────────────────────────────────────────────────────────────
    # 3. AI Incident Report
    # ──────────────────────────────────────────────────────────────
    def generate_incident_report(self, events: list[dict], score: int) -> dict:
        """Generate a full AI-assisted incident report."""
        cache_key = f"report-{score}-{len(events)}"
        if self._is_cached(cache_key):
            return self._cache[cache_key]

        mitre = build_mitre_summary(events)
        event_summaries = self._summarize_events(events)

        if not self._available:
            result = self._fallback_incident_report(events, score, mitre)
            return self._store_cache(cache_key, result)

        prompt = f"""You are Trinetra Sentinel AI generating a formal incident report.

RISK SCORE: {score}/100
TOTAL EVENTS: {len(events)}
TIMESTAMP: {datetime.now(timezone.utc).isoformat()}

EVENTS:
{event_summaries}

MITRE ATT&CK TECHNIQUES DETECTED:
{json.dumps(mitre.get('techniques', [])[:15], indent=2)}

Generate a professional incident report with these sections:

# Incident Report — Trinetra Sentinel

## Incident Overview
(Executive summary of the security incident)

## Timeline Summary
(Chronological sequence of key events with timestamps)

## Risk Assessment
(Severity classification, affected systems, data at risk)

## MITRE ATT&CK References
(Table of techniques, IDs, and tactics)

## Recommended Mitigation Steps
(Prioritized remediation plan: Immediate, Short-term, Long-term)

## Conclusion
(Overall assessment and next steps)

Use professional cybersecurity language. Keep under 800 words."""

        text = self._safe_generate(prompt, max_tokens=2048)
        if not text:
            result = self._fallback_incident_report(events, score, mitre)
            return self._store_cache(cache_key, result)

        result = {
            "report": text,
            "mitre": mitre,
            "score": score,
            "event_count": len(events),
            "provider": "gemini",
            "model": self._model_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": None,
        }
        return self._store_cache(cache_key, result)

    # ──────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────
    def _summarize_events(self, events: list[dict]) -> str:
        """Convert events to a compact text summary for the prompt."""
        lines = []
        seen_types: set[str] = set()
        type_counts = Counter(e.get("event_type", "unknown") for e in events)

        for event in events[:30]:
            et = event.get("event_type", "")
            if et in seen_types:
                continue
            seen_types.add(et)
            lines.append(
                f"- [{event.get('severity', 'low').upper()}] {event.get('title', '')} "
                f"({et}, score={event.get('score', 0)}, x{type_counts.get(et, 1)})"
            )
        return "\n".join(lines) if lines else "No events detected."

    def _is_cached(self, key: str) -> bool:
        if key in self._cache and time.monotonic() - self._cache_time < self._cache_ttl:
            return True
        return False

    def _store_cache(self, key: str, result: dict) -> dict:
        self._cache[key] = result
        self._cache_time = time.monotonic()
        return result

    # ──────────────────────────────────────────────────────────────
    # Fallback responses (when Gemini is unavailable)
    # ──────────────────────────────────────────────────────────────
    def _fallback_threat_analysis(self, events, score, mitre) -> dict:
        categories = Counter(e.get("category", "unknown") for e in events)
        severities = Counter(e.get("severity", "low") for e in events)
        high = severities.get("high", 0) + severities.get("critical", 0)

        lines = [
            "## Executive Summary",
            f"Risk score is **{score}/100**. {len(events)} events detected across "
            f"{len(categories)} categories. {high} high/critical severity alerts require attention.",
            "",
            "## Technical Analysis",
        ]
        for cat, count in categories.most_common(6):
            lines.append(f"- **{cat}**: {count} event(s)")

        lines.extend([
            "",
            "## Potential Impact",
            "- Unresolved high-severity events may lead to system compromise." if high > 0
            else "- Current event levels indicate manageable risk.",
            "",
            "## MITRE ATT&CK Coverage",
        ])
        for t in mitre.get("techniques", [])[:6]:
            lines.append(f"- **{t['technique_id']}** {t['name']} ({t['tactic']})")

        lines.extend(["", "## Recommended Actions",
                       "1. Review all high/critical alerts in the Live Threat Feed",
                       "2. Run a full Windows Defender scan",
                       "3. Check USB devices for suspicious files",
                       "4. Review registry persistence entries",
                       "5. Monitor for recurring patterns"])

        return {
            "analysis": "\n".join(lines),
            "mitre": mitre,
            "score": score,
            "event_count": len(events),
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "Gemini unavailable — using local analysis" if not self._available else "API call failed",
        }

    def _fallback_explain(self, alert, all_events) -> dict:
        event_type = alert.get("event_type", "")
        mitre_techniques = map_events_to_mitre([alert])

        explanation = (
            f"## What happened?\n"
            f"**{alert.get('title', 'Unknown event')}** was detected by the "
            f"**{alert.get('source', 'monitoring system')}**.\n\n"
            f"## Why was this alert generated?\n"
            f"This alert was triggered because the system detected **{event_type.replace('_', ' ')}** "
            f"behavior with a threat score of **{alert.get('score', 0)}/100**.\n\n"
            f"**Summary:** {alert.get('summary', 'No additional details available.')}\n\n"
            f"## Severity: {alert.get('severity', 'unknown').upper()}\n"
            f"The severity level reflects the potential impact and confidence of this detection.\n\n"
        )
        if mitre_techniques:
            explanation += "## MITRE ATT&CK Context\n"
            for t in mitre_techniques[:3]:
                explanation += f"- **{t['technique_id']}** {t['name']} — {t['description'][:100]}\n"
            explanation += "\n"

        explanation += "## What should you do?\n1. Review the alert details\n2. Check the source process\n3. Run a security scan if unsure\n"

        return {
            "explanation": explanation,
            "alert_type": event_type,
            "mitre": mitre_techniques,
            "related_events": 0,
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
        }

    def _fallback_incident_report(self, events, score, mitre) -> dict:
        categories = Counter(e.get("category", "unknown") for e in events)
        severities = Counter(e.get("severity", "low") for e in events)
        high = severities.get("high", 0) + severities.get("critical", 0)

        report = (
            f"# Incident Report — Trinetra Sentinel\n\n"
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"**Risk Score:** {score}/100\n"
            f"**Total Events:** {len(events)}\n\n"
            f"## Incident Overview\n"
            f"The endpoint monitoring system detected {len(events)} security events across "
            f"{len(categories)} categories, with {high} high/critical severity alerts.\n\n"
            f"## Risk Assessment\n"
            f"- Severity breakdown: {dict(severities)}\n"
            f"- Top categories: {', '.join(f'{c} ({n})' for c, n in categories.most_common(5))}\n\n"
            f"## MITRE ATT&CK References\n"
        )
        for t in mitre.get("techniques", [])[:8]:
            report += f"| {t['technique_id']} | {t['name']} | {t['tactic']} |\n"

        report += (
            "\n## Recommended Mitigation Steps\n"
            "### Immediate\n"
            "1. Isolate the endpoint if risk score exceeds 70\n"
            "2. Review all critical/high alerts\n\n"
            "### Short-term\n"
            "1. Run full antivirus scan\n"
            "2. Review and clean registry persistence entries\n\n"
            "### Long-term\n"
            "1. Implement application whitelisting\n"
            "2. Enable enhanced logging and monitoring\n\n"
            "## Conclusion\n"
            f"Current security posture requires {'immediate attention' if score >= 50 else 'continued monitoring'}."
        )

        return {
            "report": report,
            "mitre": mitre,
            "score": score,
            "event_count": len(events),
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "Gemini unavailable — using local report generation",
        }
