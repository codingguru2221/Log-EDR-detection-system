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
from .gemini_rate_limiter import GeminiRateLimiter
from .gemini_cache import GeminiCache


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
    """Gemini-powered threat intelligence — read-only, no system control.

    Priority: Gemini AI is used ONLY for threat analysis when severity >= medium.
    Local Trinetra Analysis activates for low-severity events or when rate limited.
    Retry delays: immediate, 3s, 5s, 10s.

    Cost optimization:
      - Severity gating: INFO/LOW -> local fallback only
      - Rate limiting: max 1 startup call, cooldown between non-critical calls
      - Persistent cache: similar incidents reuse previous analysis
      - Local analytics context: Gemini receives pre-processed reports, not raw logs
    """

    # Retry backoff schedule (seconds): attempt 1=immediate, 2=3s, 3=5s, 4=10s
    RETRY_DELAYS = [0, 3, 5, 10]

    def __init__(self):
        self._api_key = _get_env("GEMINI_API_KEY")
        self._model_name = _get_env("GEMINI_MODEL", "gemini-2.5-flash")
        self._timeout = int(_get_env("GEMINI_TIMEOUT_SECONDS", "12"))
        self._cache_ttl = int(_get_env("TRINETRA_AI_CACHE_SECONDS", "45"))
        self._model = None
        self._available = False
        self._cache: dict = {}
        self._cache_time: float = 0.0
        # Enhanced status tracking
        self._init_error: str | None = None
        self._last_error: str | None = None
        self._retry_count: int = 0
        self._connectivity_ok: bool = False
        self._status_detail: str = ""
        # Cost optimization modules
        self._rate_limiter = GeminiRateLimiter()
        self._gemini_cache = GeminiCache()
        self._startup_summary: dict | None = None

        if _HAS_GENAI and self._api_key:
            try:
                genai.configure(api_key=self._api_key)
                self._model = genai.GenerativeModel(self._model_name)
                # Validate connectivity with a lightweight probe
                ok, err = self._validate_connectivity()
                if ok:
                    self._available = True
                    self._connectivity_ok = True
                    self._status_detail = "Gemini Threat Intelligence Online"
                else:
                    self._available = False
                    self._init_error = err
                    self._status_detail = f"Connectivity check failed: {err}"
            except Exception as exc:
                self._available = False
                self._init_error = f"{type(exc).__name__}: {exc}"
                self._status_detail = f"Initialization failed: {self._init_error}"
        else:
            if not _HAS_GENAI:
                self._init_error = "google-generativeai package not installed"
            else:
                self._init_error = "GEMINI_API_KEY not set in environment or .env file"
            self._status_detail = self._init_error

    @property
    def available(self) -> bool:
        return self._available

    @property
    def init_error(self) -> str | None:
        """Reason Gemini could not initialize (None if OK)."""
        return self._init_error

    @property
    def last_error(self) -> str | None:
        """Most recent runtime error from Gemini API calls."""
        return self._last_error

    @property
    def status_detail(self) -> str:
        """Human-readable status string for the UI."""
        return self._status_detail

    # ── Connectivity validation ──────────────────────────────────────────────
    def _validate_connectivity(self) -> tuple[bool, str | None]:
        """Lightweight connectivity probe — sends a minimal request to confirm
        the API key is valid, the network is reachable, and the endpoint responds.
        Returns (success, error_reason).
        """
        if not _HAS_GENAI:
            return False, "google-generativeai package not installed"
        if not self._api_key:
            return False, "GEMINI_API_KEY not configured"
        try:
            test_model = genai.GenerativeModel(self._model_name)
            response = test_model.generate_content(
                "Respond with OK",
                generation_config=genai.GenerationConfig(max_output_tokens=8, temperature=0.0),
            )
            if response.text:
                return True, None
            return False, "Empty response from Gemini endpoint — API key may be invalid"
        except Exception as exc:
            msg = str(exc).lower()
            if "api key" in msg or "unauthenticated" in msg or "permission" in msg:
                return False, "API key is invalid or lacks permission"
            if "timeout" in msg or "deadline" in msg:
                return False, "Gemini endpoint timed out during connectivity check"
            if "network" in msg or "connection" in msg or "dns" in msg or "resolve" in msg:
                return False, "Network unreachable — check internet connection"
            return False, f"Connectivity probe failed: {type(exc).__name__}: {exc}"

    # ── Retry-enabled API caller ─────────────────────────────────────────────
    def _safe_generate(self, prompt: str, max_tokens: int = 2048) -> str | None:
        """Call Gemini with retry logic: 4 attempts with backoff [0s, 3s, 5s, 10s].

        Only after all attempts fail does this return None, triggering the local
        Trinetra Analysis fallback.
        """
        if not self._model:
            self._last_error = "Gemini model not initialized"
            return None

        last_exc: Exception | None = None
        for attempt_idx, delay in enumerate(self.RETRY_DELAYS):
            if delay > 0:
                time.sleep(delay)
            try:
                response = self._model.generate_content(
                    prompt,
                    generation_config=genai.GenerationConfig(
                        max_output_tokens=max_tokens,
                        temperature=0.3,
                    ),
                )
                text = response.text
                if text:
                    # Success — update status and reset error tracking
                    self._retry_count = attempt_idx
                    self._last_error = None
                    if attempt_idx > 0:
                        self._status_detail = (
                            f"Gemini Threat Intelligence Online (recovered after {attempt_idx} retries)"
                        )
                    else:
                        self._status_detail = "Gemini Threat Intelligence Online"
                    return text
                # Empty response — treat as failure and retry
                last_exc = ValueError("Gemini returned empty response")
            except Exception as exc:
                last_exc = exc
                msg = str(exc).lower()
                if "api key" in msg or "unauthenticated" in msg:
                    self._last_error = "API key rejected by Gemini"
                    break  # No point retrying invalid key
                if "quota" in msg or "rate limit" in msg:
                    self._last_error = "Gemini API quota exceeded"
                    # Continue retrying — quota may reset
                elif "timeout" in msg or "deadline" in msg:
                    self._last_error = "Gemini request timed out"
                elif "network" in msg or "connection" in msg:
                    self._last_error = "Network error reaching Gemini"
                else:
                    self._last_error = f"{type(exc).__name__}: {exc}"

        # All 4 attempts failed
        self._retry_count = len(self.RETRY_DELAYS)
        self._status_detail = (
            f"Gemini service temporarily unavailable after {len(self.RETRY_DELAYS)} attempts. "
            f"Using local threat intelligence as backup."
        )
        return None

    # ──────────────────────────────────────────────────────────────
    # 1. Threat Summarization
    # ──────────────────────────────────────────────────────────────
    def analyze_threat(self, events: list[dict], score: int, local_report: dict | None = None) -> dict:
        """Generate Gemini-powered threat analysis with MITRE mapping.

        Cost optimization:
          - Severity gate: only medium+ calls Gemini
          - Rate limiter: max 1 call per incident, cooldown for non-critical
          - Persistent cache: reuses analysis for similar incidents
          - Local context: uses pre-processed analytics instead of raw logs
        """
        # ── Severity gate: only medium+ triggers Gemini ──
        severity = self._rate_limiter.score_to_severity(score)
        if not self._rate_limiter.severity_allowed(severity):
            mitre = build_mitre_summary(events)
            result = self._fallback_threat_analysis(events, score, mitre)
            result["severity_gate"] = f"Blocked: severity '{severity}' below medium threshold"
            return result

        # ── Persistent cache: check for similar incident ──
        cache_key = self._gemini_cache.generate_key(events, score)
        cached = self._gemini_cache.get(cache_key)
        if cached:
            cached["provider"] = "gemini-cache"
            cached["cache_hit"] = True
            return cached

        # Also check similarity cache
        similar = self._gemini_cache.find_similar(events, score, threshold=0.65)
        if similar:
            similar["provider"] = "gemini-cache"
            similar["cache_hit"] = True
            similar["similarity_match"] = True
            return similar

        # ── Rate limiter: check if call is allowed ──
        incident_id = f"threat-{score}-{len(events)}"
        if not self._rate_limiter.allow_threat_call(severity, incident_id):
            mitre = build_mitre_summary(events)
            result = self._fallback_threat_analysis(events, score, mitre)
            cooldown = self._rate_limiter.get_cooldown_remaining()
            result["rate_limited"] = True
            result["rate_limit_detail"] = (
                f"Gemini call deferred (rate limit). Cooldown remaining: {cooldown:.0f}s"
            )
            return result

        # ── In-memory cache (existing) ──
        mem_cache_key = f"threat-{score}-{len(events)}"
        if self._is_cached(mem_cache_key):
            return self._cache[mem_cache_key]

        mitre = build_mitre_summary(events)
        event_summaries = self._summarize_events(events)

        if not self._available:
            result = self._fallback_threat_analysis(events, score, mitre)
            return self._store_cache(mem_cache_key, result)

        # Build prompt — use local analytics report if available
        local_context = ""
        if local_report:
            exec_summary = local_report.get("executive_summary", "")
            correlation_data = local_report.get("correlation", {})
            anomalies_data = local_report.get("anomalies", {})
            local_context = f"""
LOCAL ANALYTICS REPORT (pre-processed by Trinetra Sentinel):
Executive Summary: {exec_summary}
Attack Chains Detected: {correlation_data.get('chains_detected', 0)}
Anomalies Detected: {anomalies_data.get('anomalies_detected', 0)}
"""

        prompt = f"""You are Trinetra Sentinel AI, an expert SOC (Security Operations Center) analyst.
Analyze the following endpoint security data and generate a comprehensive analyst-level threat report.

CURRENT RISK SCORE: {score}/100
{local_context}
DETECTED EVENTS ({len(events)} total):
{event_summaries}

MITRE ATT&CK MAPPINGS:
{json.dumps(mitre.get('techniques', [])[:12], indent=2)}

ACTIVE TACTICS: {', '.join(mitre.get('active_tactics', []))}

For EVERY detected threat, explain each of the following in clear, professional cybersecurity language:

Provide your report in this EXACT markdown format:

## Executive Summary
(2–3 sentences: overall posture, most significant finding, urgency level)

## What Happened?
(Describe each detected security event in plain language. Group related events together. Include timestamps or event counts where relevant.)

## How Was It Detected?
(Explain the indicators that triggered detection — process chains, registry changes, log anomalies, USB activity, authentication failures, etc.)

## Why Is It Suspicious?
(Explain the analyst reasoning — why these indicators together form a credible threat. Reference behavioral patterns.)

## How Did It Likely Occur?
(Explain the probable attack path or initial access vector — phishing, compromised credentials, USB-borne malware, lateral movement, etc.)

## Potential Impact
(What could happen if this threat is not addressed — data exfiltration, ransomware, privilege escalation, persistent access, system compromise.)

## MITRE ATT&CK Coverage
(List the top 5–8 mapped techniques. For each, provide the ID, technique name, and tactic phase.)

## Recommended Actions
(Provide 5–7 prioritized mitigation steps, ordered from immediate containment to long-term hardening.)
"""
        text = self._safe_generate(prompt)
        if not text:
            result = self._fallback_threat_analysis(events, score, mitre)
            return self._store_cache(mem_cache_key, result)

        result = {
            "analysis": text,
            "mitre": mitre,
            "score": score,
            "event_count": len(events),
            "provider": "gemini",
            "model": self._model_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": None,
            "status": self._status_detail,
        }

        # Store in both in-memory and persistent cache
        self._store_cache(mem_cache_key, result)
        result_with_sig = {**result, "_similarity_sig": list(
            self._gemini_cache.generate_similarity_signature(events, score)
        )}
        self._gemini_cache.set(cache_key, result_with_sig)

        return result

    # ──────────────────────────────────────────────────────────────
    # 2. Explainable Alerts
    # ──────────────────────────────────────────────────────────────
    def explain_alert(self, alert: dict, all_events: list[dict]) -> dict:
        """Explain why a specific alert was generated.

        Only calls Gemini for medium+ severity alerts.
        """
        # Severity gate: check alert severity
        alert_severity = (alert.get("severity") or "low").lower().strip()
        if not self._rate_limiter.severity_allowed(alert_severity):
            return self._fallback_explain(alert, all_events)

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
        """Generate a full AI-assisted incident report.

        Only calls Gemini for medium+ severity. Uses cache and rate limiter.
        """
        # Severity gate
        severity = self._rate_limiter.score_to_severity(score)
        if not self._rate_limiter.severity_allowed(severity):
            mitre = build_mitre_summary(events)
            result = self._fallback_incident_report(events, score, mitre)
            result["severity_gate"] = f"Blocked: severity '{severity}' below medium threshold"
            return result

        cache_key = f"report-{score}-{len(events)}"
        if self._is_cached(cache_key):
            return self._cache[cache_key]

        # Check persistent cache
        pcache_key = self._gemini_cache.generate_key(events, score)
        cached = self._gemini_cache.get(pcache_key)
        if cached and "report" in cached:
            cached["provider"] = "gemini-cache"
            return cached

        # Rate limiter
        incident_id = f"report-{score}-{len(events)}"
        if not self._rate_limiter.allow_threat_call(severity, incident_id):
            mitre = build_mitre_summary(events)
            result = self._fallback_incident_report(events, score, mitre)
            result["rate_limited"] = True
            return result

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
    # 4. Conversational Voice Response (ChatGPT Voice / Gemini Live style)
    # ──────────────────────────────────────────────────────────────
    def conversational_response(
        self,
        user_question: str,
        events: list[dict],
        score: int,
        language: str = "en",
        processes: list[dict] | None = None,
        snapshot: dict | None = None,
        conversation_history: list[dict] | None = None,
    ) -> dict:
        """Generate a natural, voice-optimized conversational response.

        The response is written specifically for spoken delivery —
        short sentences, natural pauses, no markdown, no bullet points.
        """
        if not user_question or not user_question.strip():
            return {
                "response": "I'm here to help. Ask me anything about your system security.",
                "provider": "local-fallback",
                "language": language,
            }

        # Build context snapshot
        categories = Counter(e.get("category", "unknown") for e in events[:80])
        severities = Counter(e.get("severity", "low") for e in events[:80])
        high_count = severities.get("high", 0) + severities.get("critical", 0)
        top_procs = sorted(processes or [], key=lambda p: p.get("cpu", 0), reverse=True)[:3]
        proc_text = ", ".join(f"{p.get('name')} ({p.get('cpu',0)}% CPU)" for p in top_procs) or "none"

        # Recent event summary for context
        recent_types = Counter(e.get("event_type", "unknown") for e in events[:40])
        event_summary = "; ".join(f"{t.replace('_',' ')} ({c})" for t, c in recent_types.most_common(6))

        # Build conversation history for context
        history_text = ""
        if conversation_history:
            history_lines = []
            for msg in conversation_history[-6:]:
                role = "User" if msg.get("role") == "user" else "Trinetra"
                history_lines.append(f"{role}: {msg.get('text', '')[:200]}")
            history_text = "\nCONVERSATION HISTORY:\n" + "\n".join(history_lines)

        # Language instruction
        lang_map = {
            "en": "English",
            "hi": "Hindi (use Devanagari script)",
            "mr": "Marathi (use Devanagari script)",
            "gu": "Gujarati (use Gujarati script)",
            "te": "Telugu (use Telugu script)",
            "ta": "Tamil (use Tamil script)",
            "kn": "Kannada (use Kannada script)",
            "ml": "Malayalam (use Malayalam script)",
            "bn": "Bengali (use Bengali script)",
            "pa": "Punjabi (use Gurmukhi script)",
            "or": "Odia (use Odia script)",
            "as": "Assamese (use Bengali script)",
        }
        lang_name = lang_map.get(language, "English")

        if not self._available:
            fallback_text = self._fallback_conversational(user_question, events, score, language)
            return {
                "response": fallback_text,
                "provider": "local-fallback",
                "model": "trinetra-algorithm",
                "language": language,
            }

        prompt = f"""You are Trinetra Sentinel, a senior SOC (Security Operations Center) analyst delivering a live executive voice briefing to a stakeholder.
You are speaking directly to the user in a natural, human-like conversation.

CRITICAL RULES FOR VOICE DELIVERY:
- Write ONLY in {lang_name}. Do not mix languages.
- Speak as a real SOC analyst would — confident, calm, professional but approachable.
- Use short sentences with natural pauses, as if speaking aloud.
- Do NOT use markdown, bullet points, headers, bold, or any formatting whatsoever.
- Do NOT read raw data, event IDs, or technical jargon — translate everything into plain language.
- Sound like you are giving an executive security briefing, not reading a report.
- Keep your response under 80 words.
- End with a follow-up question or offer to help further when appropriate.
- If the threat level is critical or high, convey urgency calmly without alarming the user.
- If everything is fine, sound reassuring and professional.

CURRENT SYSTEM STATUS:
- Risk score: {score}/100
- Total recent events: {len(events[:80])}
- High/critical alerts: {high_count}
- Top categories: {', '.join(f"{c} ({n})" for c, n in categories.most_common(4))}
- Event types: {event_summary}
- Top processes: {proc_text}
- Detected events: {len(events)}
{history_text}

USER QUESTION: {user_question}

Respond as a real SOC analyst would speak — natural, concise, no formatting, just spoken language."""

        text = self._safe_generate(prompt, max_tokens=300)
        if not text:
            fallback_text = self._fallback_conversational(user_question, events, score, language)
            return {
                "response": fallback_text,
                "provider": "local-fallback",
                "model": "trinetra-algorithm",
                "language": language,
            }

        # Clean any accidental markdown from Gemini output
        import re
        clean = text.strip()
        clean = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = re.sub(r"#{1,6}\s*", "", clean)
        clean = re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean)
        clean = re.sub(r"^\s*[-*+]\s+", "", clean, flags=re.MULTILINE)
        clean = re.sub(r"\n+", " ", clean).strip()

        return {
            "response": clean,
            "provider": "gemini",
            "model": self._model_name,
            "language": language,
        }

    def _fallback_conversational(self, question: str, events: list[dict], score: int, language: str) -> str:
        """Local fallback for conversational responses when Gemini is unavailable."""
        q = question.lower()
        high_count = sum(1 for e in events[:80] if e.get("severity") in {"high", "critical"})

        if language == "hi":
            if any(kw in q for kw in ("risk", "threat", "danger", "score", "safe")):
                if score >= 50:
                    return f"Aapke system ka risk score {score} out of 100 hai. {high_count} high severity alerts hain. Turant review karna zaroori hai. Kya main aapko details bataoon?"
                return f"Aapka system surakshit hai. Risk score {score} out of 100 hai. Koi gambhir khatra nahi hai. Kya aap kuch aur jaanna chahte hain?"
            if any(kw in q for kw in ("usb", "device", "drive")):
                return "USB activity check karne par kuch external devices detect hue hain. Scan karna behtar hoga. Kya main details bataoon?"
            if any(kw in q for kw in ("process", "cpu", "memory")):
                return "System processes mein kuch heavy resource users hain. Kya main aapko top processes ki list doon?"
            if score >= 50:
                return f"Dhyaan dein, aapke system ka risk score {score} hai. {high_count} gambhir alerts hain jo turant samiksha chahte hain. Kya main aapko guide karoon?"
            return f"Sab theek lag raha hai. Risk score {score} hai. Koi badi chinta nahi hai. Kya aap kuch aur jaanna chahte hain?"

        if language == "mr":
            if score >= 50:
                return f"Tumcha system cha risk score {score} ahe. {high_count} gambhir alerts aahet. Kripya lavkar review kara. Mee tula guide karu shakta?"
            return f"System surakshit ahe. Risk score {score} ahe. Mothi chinta nahi ahe. Tula ajun kahi mahiti havay ka?"

        if language == "gu":
            if score >= 50:
                return f"Tamaru system nu risk score {score} che. {high_count} gambhir alerts che. Kripya turant review karo. Hu tamne guide karu?"
            return f"System surakshit che. Risk score {score} che. Koi moti chinta nathi. Tame bija kahi janva mango cho?"

        if language == "te":
            if score >= 50:
                return f"Mee system risk score {score} undi. {high_count} high severity alerts unnayi. Ventane review cheyandi. Nenu mee help cheyana?"
            return f"System surakshitamga undi. Risk score {score}. Pedda samasya ledu. Inka emaina teliyali aa?"

        # English (default)
        if any(kw in q for kw in ("ransomware", "malware", "virus")):
            return f"Ransomware is malicious software that locks your files and demands payment. It usually spreads through phishing emails or infected downloads. I recommend keeping your backups updated and running regular scans. Would you like me to explain how to protect your system?"

        if any(kw in q for kw in ("risk", "threat", "danger", "score", "safe", "secure")):
            if score >= 70:
                return f"Warning. Your system risk score is {score} out of 100 with {high_count} high severity alerts. This needs immediate attention. I recommend reviewing all critical alerts and isolating the affected system if needed. Shall I walk you through the investigation?"
            if score >= 40:
                return f"Your risk score is {score} out of 100. There are some indicators worth reviewing but nothing critical right now. I suggest keeping an eye on the alerts. Want me to explain any specific event?"
            return f"Everything looks good. Your risk score is {score} out of 100 and I haven't detected any significant threats. Your system appears secure. Is there anything specific you'd like me to check?"

        if any(kw in q for kw in ("what should i do", "next step", "recommend", "help", "action")):
            if high_count > 0:
                return f"The first step is to review the {high_count} high severity alerts in your threat feed. After that, isolate any affected devices and run a full security scan. Would you like me to guide you through each step?"
            return "Your system looks healthy right now. I recommend running periodic scans and keeping monitoring active. Would you like any specific security tips?"

        if any(kw in q for kw in ("usb", "device", "drive", "external")):
            return "I detected some USB activity on your system. External drives can sometimes carry malicious files. I recommend scanning any connected device before opening files. Would you like to see the scan results?"

        if any(kw in q for kw in ("process", "cpu", "memory", "ram", "resource", "slow")):
            return "I can see some processes consuming notable resources. High CPU or memory usage can slow things down. I recommend checking the Performance Optimizer panel to identify what can be safely stopped. Want me to list the top resource consumers?"

        if any(kw in q for kw in ("summary", "overview", "status", "how is", "what's happening")):
            if score >= 50:
                return f"Your system currently has a risk score of {score} with {high_count} high severity alerts. There are active threat indicators that need your attention. Shall I break down the findings for you?"
            return f"Your system is in good shape with a risk score of {score}. No major threats detected at the moment. Monitoring is active and everything looks stable. Anything specific you'd like to know?"

        # General fallback
        if score >= 50:
            return f"Your risk score is currently {score} with {high_count} alerts requiring attention. I'm here to help you understand and respond to any security events. What would you like to know?"
        return f"Your system is running normally with a risk score of {score}. I'm monitoring everything and I'm here if you have any questions. What would you like to know about your security?"

    # ──────────────────────────────────────────────────────────────
    # 5. Investigation Assistant — collects logs, correlates, builds timeline
    # ──────────────────────────────────────────────────────────────
    def investigate_threat(
        self,
        user_question: str,
        events: list[dict],
        score: int,
        language: str = "en",
        processes: list[dict] | None = None,
        conversation_history: list[dict] | None = None,
    ) -> dict:
        """Deep investigation: collect logs, correlate events, build timeline, explain findings."""
        import re as _re

        # Build detailed event timeline
        timeline_events = sorted(events[:60], key=lambda e: e.get("timestamp", ""))
        timeline_lines = []
        for ev in timeline_events[:20]:
            ts = ev.get("timestamp", "")[:19]
            timeline_lines.append(
                f"[{ts}] {ev.get('severity','?').upper()} - {ev.get('title','')} "
                f"({ev.get('event_type','')}) score={ev.get('score',0)}"
            )
        timeline_text = "\n".join(timeline_lines) if timeline_lines else "No events in timeline."

        # Correlated threat chains
        from collections import Counter as _C
        threat_types = _C(e.get("event_type", "unknown") for e in events[:80])
        high_events = [e for e in events[:80] if e.get("severity") in {"high", "critical"}]
        mitre = build_mitre_summary(events[:80])

        # Process context
        top_procs = sorted(processes or [], key=lambda p: p.get("cpu", 0), reverse=True)[:5]
        proc_lines = [f"{p.get('name','?')} PID={p.get('pid','?')} CPU={p.get('cpu',0)}% MEM={p.get('memory',0)}%" for p in top_procs]
        proc_text = "\n".join(proc_lines) if proc_lines else "No process snapshot."

        # Conversation history
        history_text = ""
        if conversation_history:
            history_lines = []
            for msg in conversation_history[-8:]:
                role = "User" if msg.get("role") == "user" else "Trinetra"
                history_lines.append(f"{role}: {msg.get('text', '')[:250]}")
            history_text = "\nCONVERSATION HISTORY:\n" + "\n".join(history_lines)

        lang_map = {
            "en": "English",
            "hi": "Hindi (use Devanagari script)",
            "mr": "Marathi (use Devanagari script)",
            "gu": "Gujarati (use Gujarati script)",
            "te": "Telugu (use Telugu script)",
        }
        lang_name = lang_map.get(language, "English")

        if not self._available:
            return self._fallback_investigation(events, score, high_events, language)

        prompt = f"""You are Trinetra Sentinel, an AI cybersecurity investigator conducting a deep investigation.

INVESTIGATION REQUEST: {user_question}

EVENT TIMELINE (chronological):
{timeline_text}

THREAT INDICATORS:
- Risk score: {score}/100
- High/critical events: {len(high_events)}
- Event type distribution: {', '.join(f"{t} ({c})" for t, c in threat_types.most_common(8))}

ACTIVE PROCESSES:
{proc_text}

MITRE ATT&CK TECHNIQUES:
{json.dumps(mitre.get('techniques', [])[:10], indent=2)}
{history_text}

Provide a thorough INVESTIGATION REPORT in {lang_name}. Rules:
- Write ONLY in {lang_name}. No mixing languages.
- Speak naturally as if briefing a security team.
- NO markdown, NO bullet points, NO headers, NO formatting.
- Use short conversational sentences suitable for voice delivery.
- Cover: what happened, how detected, why suspicious, likely attack path, affected systems, potential impact, severity assessment, recommended actions.
- Keep under 120 words.
- End by asking if the user wants to start guided remediation."""

        text = self._safe_generate(prompt, max_tokens=500)
        if not text:
            return self._fallback_investigation(events, score, high_events, language)

        # Clean markdown
        clean = text.strip()
        clean = _re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = _re.sub(r"#{1,6}\s*", "", clean)
        clean = _re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = _re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean)
        clean = _re.sub(r"^\s*[-*+]\s+", "", clean, flags=_re.MULTILINE)
        clean = _re.sub(r"\n+", " ", clean).strip()

        return {
            "response": clean,
            "mode": "investigation",
            "findings_count": len(high_events),
            "timeline_events": len(timeline_events),
            "provider": "gemini",
            "model": self._model_name,
            "language": language,
        }

    def _fallback_investigation(self, events, score, high_events, language):
        """Local fallback investigation report."""
        from collections import Counter as _C
        high_count = len(high_events)
        types = _C(e.get("event_type", "unknown") for e in high_events)
        type_detail = ", ".join(f"{t.replace('_',' ')} ({c})" for t, c in types.most_common(4))

        if language == "hi":
            if high_count > 0:
                return {"response": f"Maine investigation ki hai. {high_count} gambhir ghatnaayein mili hain jaise {type_detail}. Ye suspicious activity darshati hai. Risk score {score} hai. Main aapko step by step guide kar sakta hoon. Kya shuru karein?", "mode": "investigation", "provider": "local-fallback", "language": language}
            return {"response": f"Investigation mein koi gambhir khatra nahi mila. Risk score {score} hai. System theek lag raha hai. Kya aap kuch aur jaanna chahte hain?", "mode": "investigation", "provider": "local-fallback", "language": language}

        if high_count > 0:
            response = (
                f"I have completed my investigation. I found {high_count} high severity events including {type_detail}. "
                f"The risk score is {score} out of 100. These indicators suggest a potential security incident that needs attention. "
                f"The event timeline shows activity patterns consistent with suspicious behavior. "
                f"I recommend we begin step-by-step remediation. Would you like me to guide you through the resolution process?"
            )
        else:
            response = (
                f"My investigation shows no critical threats at this time. The risk score is {score} out of 100. "
                f"While there are some events in the logs, none appear to indicate active compromise. "
                f"I recommend continuing to monitor and running periodic scans. "
                f"Would you like me to explain any specific event in more detail?"
            )

        return {
            "response": response,
            "mode": "investigation",
            "findings_count": high_count,
            "timeline_events": len(events[:60]),
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
            "language": language,
        }

    # ──────────────────────────────────────────────────────────────
    # 6. Guided Remediation — step-by-step interactive resolution
    # ──────────────────────────────────────────────────────────────
    def guided_remediation(
        self,
        user_input: str,
        events: list[dict],
        score: int,
        language: str = "en",
        current_step: int = 0,
        completed_steps: list[str] | None = None,
        conversation_history: list[dict] | None = None,
    ) -> dict:
        """Generate the next guided remediation step.

        Args:
            user_input: What the user said (e.g. 'done', 'what happened', step result)
            current_step: Which step we're on (0 = start)
            completed_steps: List of steps already completed
        """
        import re as _re

        completed = completed_steps or []
        high_events = [e for e in events[:80] if e.get("severity") in {"high", "critical"}]
        high_count = len(high_events)

        # Build remediation context
        threat_types = set(e.get("event_type", "") for e in high_events)
        has_usb = any("usb" in t for t in threat_types)
        has_ransomware = "ransomware_activity" in threat_types
        has_brute_force = any(t in threat_types for t in ("failed_login", "account_lockout"))
        has_persistence = "registry_persistence" in threat_types
        has_file_threats = any(t in threat_types for t in ("mass_file_deletion", "mass_file_rename", "bulk_file_modification"))

        # Standard remediation playbook
        playbook = []
        if has_ransomware or score >= 70:
            playbook.append("Disconnect the affected device from the network immediately")
        if has_brute_force:
            playbook.append("Review authentication logs and block suspicious IP addresses")
        if has_usb:
            playbook.append("Eject and physically disconnect any USB storage devices")
        playbook.append("Open Windows Event Viewer and navigate to Security Logs")
        playbook.append("Identify suspicious login events or process creation entries")
        if has_persistence:
            playbook.append("Check registry Run keys and scheduled tasks for persistence mechanisms")
        playbook.append("Run a full Windows Defender scan on all drives")
        if has_file_threats:
            playbook.append("Verify file integrity and restore any deleted critical files from backup")
        playbook.append("Review active processes and terminate anything suspicious")
        playbook.append("Verify the threat indicators are no longer present")

        # Determine current and next step
        total_steps = len(playbook)
        next_step_idx = min(current_step, total_steps - 1)
        current_instruction = playbook[next_step_idx] if next_step_idx < total_steps else None
        is_complete = current_step >= total_steps

        # History
        history_text = ""
        if conversation_history:
            history_lines = []
            for msg in conversation_history[-8:]:
                role = "User" if msg.get("role") == "user" else "Trinetra"
                history_lines.append(f"{role}: {msg.get('text', '')[:250]}")
            history_text = "\nCONVERSATION HISTORY:\n" + "\n".join(history_lines)

        lang_map = {
            "en": "English",
            "hi": "Hindi (use Devanagari script)",
            "mr": "Marathi (use Devanagari script)",
            "gu": "Gujarati (use Gujarati script)",
            "te": "Telugu (use Telugu script)",
        }
        lang_name = lang_map.get(language, "English")

        if not self._available:
            return self._fallback_guided_step(
                user_input, score, current_step, total_steps,
                current_instruction, is_complete, completed, language
            )

        prompt = f"""You are Trinetra Sentinel, guiding a user through step-by-step threat remediation.

CURRENT STATUS:
- Risk score: {score}/100
- High/critical alerts: {high_count}
- Threat types detected: {', '.join(threat_types) if threat_types else 'none'}
- Current step: {current_step + 1} of {total_steps}
- Completed steps: {', '.join(completed) if completed else 'none'}
{history_text}

REMEDIATION PLAYBOOK:
{chr(10).join(f"Step {i+1}: {s}" for i, s in enumerate(playbook))}

USER SAID: {user_input}

YOUR TASK:
- If user says they completed the step, acknowledge and give the NEXT step clearly.
- If user asks a question, answer it conversationally then remind them of the current step.
- If all steps are done, verify resolution and confirm the threat is resolved.
- Write ONLY in {lang_name}.
- NO markdown, NO bullet points, NO formatting.
- Short conversational sentences for voice.
- Keep under 80 words.
- Always end by asking the user to confirm when they're ready for the next step."""

        text = self._safe_generate(prompt, max_tokens=400)
        if not text:
            return self._fallback_guided_step(
                user_input, score, current_step, total_steps,
                current_instruction, is_complete, completed, language
            )

        clean = text.strip()
        clean = _re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = _re.sub(r"#{1,6}\s*", "", clean)
        clean = _re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = _re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean)
        clean = _re.sub(r"\n+", " ", clean).strip()

        # Determine if step was completed
        user_lower = user_input.lower()
        step_advanced = any(kw in user_lower for kw in ("done", "complete", "finished", "yes", "ok", "next", "ready", "ho gaya", "kar diya"))
        new_step = current_step + 1 if step_advanced and not is_complete else current_step

        return {
            "response": clean,
            "mode": "guided_remediation",
            "current_step": new_step,
            "total_steps": total_steps,
            "step_instruction": playbook[new_step] if new_step < total_steps else None,
            "is_complete": new_step >= total_steps,
            "step_advanced": step_advanced,
            "completed_steps": completed + ([current_instruction] if step_advanced and current_instruction else []),
            "provider": "gemini",
            "model": self._model_name,
            "language": language,
        }

    def _fallback_guided_step(self, user_input, score, current_step, total_steps,
                              current_instruction, is_complete, completed, language):
        """Local fallback for guided remediation steps."""
        user_lower = user_input.lower()
        step_advanced = any(kw in user_lower for kw in ("done", "complete", "finished", "yes", "ok", "next", "ready"))
        new_step = current_step + 1 if step_advanced and not is_complete else current_step

        if is_complete or new_step >= total_steps:
            if language == "hi":
                return {"response": "Bahut badhiya. Saare steps complete ho gaye hain. Ab main system ko verify karunga ki khatra tal gaya hai ya nahi. Kya main verification shuru karoon?", "mode": "guided_remediation", "current_step": new_step, "total_steps": total_steps, "step_instruction": None, "is_complete": True, "step_advanced": True, "completed_steps": completed, "provider": "local-fallback", "language": language}
            return {"response": "Great work. All remediation steps are now complete. I would like to verify that the threat has been fully resolved. Shall I run a verification check now?", "mode": "guided_remediation", "current_step": new_step, "total_steps": total_steps, "step_instruction": None, "is_complete": True, "step_advanced": True, "completed_steps": completed, "provider": "local-fallback", "language": language}

        if current_instruction:
            if language == "hi":
                return {"response": f"Step {new_step + 1} mein, aapko ye karna hai: {current_instruction}. Jab ye ho jaaye toh mujhe bata dijiye.", "mode": "guided_remediation", "current_step": new_step, "total_steps": total_steps, "step_instruction": current_instruction, "is_complete": False, "step_advanced": step_advanced, "completed_steps": completed, "provider": "local-fallback", "language": language}
            return {"response": f"For step {new_step + 1}, please do this: {current_instruction}. Let me know when you have completed this step.", "mode": "guided_remediation", "current_step": new_step, "total_steps": total_steps, "step_instruction": current_instruction, "is_complete": False, "step_advanced": step_advanced, "completed_steps": completed, "provider": "local-fallback", "language": language}

        return {"response": "Let's begin the guided remediation process. I'll walk you through each step. Are you ready to start?", "mode": "guided_remediation", "current_step": 0, "total_steps": total_steps, "step_instruction": None, "is_complete": False, "step_advanced": False, "completed_steps": [], "provider": "local-fallback", "language": language}

    # ──────────────────────────────────────────────────────────────
    # 7. Resolution Verification — recheck logs, confirm clean
    # ──────────────────────────────────────────────────────────────
    def verify_resolution(
        self,
        events: list[dict],
        score: int,
        language: str = "en",
        previous_score: int = 0,
        conversation_history: list[dict] | None = None,
    ) -> dict:
        """Verify that a threat has been resolved by rechecking current indicators."""
        import re as _re

        high_events = [e for e in events[:80] if e.get("severity") in {"high", "critical"}]
        high_count = len(high_events)
        recent_events = events[:20]
        active_threats = [e for e in recent_events if e.get("severity") in {"high", "critical"}]
        score_improved = previous_score > 0 and score < previous_score

        # Determine resolution status
        is_resolved = high_count == 0 and score < 30
        partial = high_count <= 2 and score < 50

        # History
        history_text = ""
        if conversation_history:
            history_lines = []
            for msg in conversation_history[-6:]:
                role = "User" if msg.get("role") == "user" else "Trinetra"
                history_lines.append(f"{role}: {msg.get('text', '')[:200]}")
            history_text = "\nCONVERSATION HISTORY:\n" + "\n".join(history_lines)

        lang_map = {
            "en": "English",
            "hi": "Hindi (use Devanagari script)",
            "mr": "Marathi (use Devanagari script)",
            "gu": "Gujarati (use Gujarati script)",
            "te": "Telugu (use Telugu script)",
        }
        lang_name = lang_map.get(language, "English")

        if not self._available:
            return self._fallback_verification(score, high_count, is_resolved, partial, language)

        prompt = f"""You are Trinetra Sentinel, performing a resolution verification check.

VERIFICATION RESULTS:
- Current risk score: {score}/100 (was {previous_score}/100 before remediation)
- Active high/critical alerts: {high_count}
- Score improved: {'Yes' if score_improved else 'No'}
- Recent events (last 20): {len(recent_events)}
- Active threats in recent: {len(active_threats)}
- Resolution status: {'RESOLVED' if is_resolved else 'PARTIAL' if partial else 'ONGOING'}
{history_text}

Generate a verification report in {lang_name}. Rules:
- Write ONLY in {lang_name}. No mixing languages.
- NO markdown, NO bullet points, NO formatting.
- Short conversational sentences for voice delivery.
- If resolved: confirm the threat appears resolved, no indicators remain.
- If partial: explain what improved but what still needs attention.
- If ongoing: explain that threats persist and what to do next.
- Keep under 80 words.
- Sound like a professional security analyst confirming findings."""

        text = self._safe_generate(prompt, max_tokens=350)
        if not text:
            return self._fallback_verification(score, high_count, is_resolved, partial, language)

        clean = text.strip()
        clean = _re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = _re.sub(r"#{1,6}\s*", "", clean)
        clean = _re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = _re.sub(r"\n+", " ", clean).strip()

        return {
            "response": clean,
            "mode": "verification",
            "is_resolved": is_resolved,
            "partial_resolution": partial,
            "current_score": score,
            "previous_score": previous_score,
            "remaining_alerts": high_count,
            "provider": "gemini",
            "model": self._model_name,
            "language": language,
        }

    def _fallback_verification(self, score, high_count, is_resolved, partial, language):
        """Local fallback for verification."""
        if is_resolved:
            if language == "hi":
                response = "Verification complete. Khatra tal gaya hai. Risk score ab normal hai aur koi gambhir alert nahi hai. Aapka system surakshit hai."
            else:
                response = "Verification complete. The threat appears to be resolved. I no longer detect indicators associated with the original security event. Your risk score has returned to normal and no high severity alerts remain. Your system is secure."
        elif partial:
            if language == "hi":
                response = f"Verification mein kuch sudhar dikha hai lekin abhi bhi {high_count} alerts hain jo dhyan chahte hain. Risk score {score} hai. Kripya baki alerts ki samiksha karein."
            else:
                response = f"Verification shows some improvement but there are still {high_count} alerts requiring attention. The risk score is {score} out of 100. I recommend continuing to review the remaining alerts before we can confirm full resolution."
        else:
            if language == "hi":
                response = f"Abhi bhi {high_count} gambhir alerts active hain. Risk score {score} hai. Khatra abhi bhi bana hua hai. Kya hum remediation continue karein?"
            else:
                response = f"There are still {high_count} active high severity alerts and the risk score remains at {score}. The threat has not been fully resolved yet. Would you like to continue with the remediation steps?"

        return {
            "response": response,
            "mode": "verification",
            "is_resolved": is_resolved,
            "partial_resolution": partial,
            "current_score": score,
            "previous_score": 0,
            "remaining_alerts": high_count,
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
            "language": language,
        }

    # ──────────────────────────────────────────────────────────────
    # 8. Startup Summary — Single Gemini call on application launch
    # ──────────────────────────────────────────────────────────────
    def generate_startup_summary(self, events: list[dict], score: int) -> dict:
        """Generate a one-time system health summary on application startup.

        Uses the rate limiter to ensure maximum 1 Gemini call per session.
        If Gemini is unavailable or rate limited, returns a local fallback.

        Returns:
            dict with summary text, system health, and security posture.
        """
        # Return cached startup summary if already generated
        if self._startup_summary is not None:
            return self._startup_summary

        # Check rate limiter — max 1 startup call per session
        if not self._rate_limiter.allow_startup_call():
            result = self._fallback_startup_summary(events, score)
            self._startup_summary = result
            return result

        if not self._available:
            result = self._fallback_startup_summary(events, score)
            self._startup_summary = result
            return result

        from collections import Counter as _C
        categories = _C(e.get("category", "unknown") for e in events[:80])
        severities = _C(e.get("severity", "low") for e in events[:80])
        high_count = severities.get("high", 0) + severities.get("critical", 0)

        prompt = f"""You are Trinetra Sentinel AI, providing a brief startup security briefing.

SYSTEM STATUS AT STARTUP:
- Risk score: {score}/100
- Total recent events: {len(events[:80])}
- High/critical alerts: {high_count}
- Top categories: {', '.join(f"{c} ({n})" for c, n in categories.most_common(5))}
- Severity breakdown: {dict(severities)}

Generate a concise startup security briefing (under 100 words) covering:
1. System health summary (is the system healthy or compromised?)
2. Recent security posture overview (any active threats?)
3. Threat monitoring status (are collectors working?)

Use professional but accessible language. No markdown formatting."""

        text = self._safe_generate(prompt, max_tokens=300)
        if not text:
            result = self._fallback_startup_summary(events, score)
            self._startup_summary = result
            return result

        import re
        clean = text.strip()
        clean = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = re.sub(r"#{1,6}\s*", "", clean)
        clean = re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = re.sub(r"\n+", " ", clean).strip()

        result = {
            "summary": clean,
            "score": score,
            "high_alerts": high_count,
            "provider": "gemini",
            "model": self._model_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "startup_summary",
        }
        self._startup_summary = result
        return result

    def _fallback_startup_summary(self, events: list[dict], score: int) -> dict:
        """Local fallback for startup summary when Gemini is unavailable."""
        from collections import Counter as _C
        severities = _C(e.get("severity", "low") for e in events[:80])
        high_count = severities.get("high", 0) + severities.get("critical", 0)
        total = len(events[:80])

        if score >= 80:
            summary = (
                f"Trinetra Sentinel startup complete. Warning: your system risk score is "
                f"{score} out of 100 with {high_count} high severity alerts. The security posture "
                f"indicates a potential active threat. All monitoring engines are initialized and "
                f"tracking {total} recent events. I recommend reviewing critical alerts immediately."
            )
        elif score >= 50:
            summary = (
                f"Trinetra Sentinel startup complete. Your system risk score is {score} out of 100. "
                f"There are {high_count} elevated alerts that need attention. All monitoring engines "
                f"are active and tracking {total} recent events. I suggest reviewing the threat feed."
            )
        elif score >= 20:
            summary = (
                f"Trinetra Sentinel startup complete. Risk score is {score} out of 100, indicating "
                f"minor indicators worth monitoring. {total} events are being tracked. All security "
                f"engines are operational. No immediate action required, but stay vigilant."
            )
        else:
            summary = (
                f"Trinetra Sentinel startup complete. Your system is secure with a risk score of "
                f"{score} out of 100. All monitoring engines are active and tracking {total} events. "
                f"No threats detected. I will continue monitoring and alert you if anything changes."
            )

        return {
            "summary": summary,
            "score": score,
            "high_alerts": high_count,
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "startup_summary",
        }

    # ──────────────────────────────────────────────────────────────
    # 9. Analyze with Local Context — Gemini receives pre-processed analytics
    # ──────────────────────────────────────────────────────────────
    def analyze_with_local_context(self, analytics_report: dict, score: int) -> dict:
        """Analyze using pre-processed local analytics instead of raw logs.

        This is the preferred way to call Gemini — it receives a structured
        report from LocalAnalyticsEngine, not raw event data.

        Args:
            analytics_report: Output from LocalAnalyticsEngine.generate_report()
            score: Current risk score

        Returns:
            Gemini analysis or local fallback.
        """
        severity = self._rate_limiter.score_to_severity(score)

        # Severity gate
        if not self._rate_limiter.severity_allowed(severity):
            return {
                "analysis": analytics_report.get("executive_summary", "System operating normally."),
                "provider": "local-analytics",
                "model": "trinetra-algorithm",
                "score": score,
                "severity_gate": f"Blocked: severity '{severity}' below medium threshold",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Rate limiter
        incident_id = f"local-ctx-{score}"
        if not self._rate_limiter.allow_threat_call(severity, incident_id):
            return {
                "analysis": analytics_report.get("report", analytics_report.get("executive_summary", "")),
                "provider": "local-analytics",
                "model": "trinetra-algorithm",
                "score": score,
                "rate_limited": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        if not self._available:
            return {
                "analysis": analytics_report.get("report", analytics_report.get("executive_summary", "")),
                "provider": "local-analytics",
                "model": "trinetra-algorithm",
                "score": score,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        # Build a focused prompt with the local report
        report_text = analytics_report.get("report", "")
        exec_summary = analytics_report.get("executive_summary", "")
        correlation = analytics_report.get("correlation", {})
        anomalies = analytics_report.get("anomalies", {})

        prompt = f"""You are Trinetra Sentinel AI, an expert SOC analyst reviewing a local security analytics report.

LOCAL ANALYTICS REPORT:
{report_text[:2000]}

EXECUTIVE SUMMARY: {exec_summary}
ATTACK CHAINS DETECTED: {correlation.get('chains_detected', 0)}
ANOMALIES DETECTED: {anomalies.get('anomalies_detected', 0)}
RISK SCORE: {score}/100

Based on this pre-processed analytics report, provide:
1. Analyst-level explanation of the security situation
2. Executive summary for leadership
3. Recommended mitigations prioritized by urgency

Keep your response under 400 words. Use markdown formatting."""

        text = self._safe_generate(prompt, max_tokens=1024)
        if not text:
            return {
                "analysis": analytics_report.get("report", exec_summary),
                "provider": "local-analytics",
                "model": "trinetra-algorithm",
                "score": score,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        return {
            "analysis": text,
            "provider": "gemini",
            "model": self._model_name,
            "score": score,
            "local_context": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ──────────────────────────────────────────────────────────────
    # 10. Stats — expose rate limiter and cache statistics
    # ──────────────────────────────────────────────────────────────
    def get_rate_limiter_stats(self) -> dict:
        """Return rate limiter statistics for the UI."""
        return self._rate_limiter.get_stats()

    def get_cache_stats(self) -> dict:
        """Return persistent cache statistics for the UI."""
        return self._gemini_cache.stats()

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

        # Build enhanced error message for the UI
        if not self._available:
            error_msg = (
                f"Gemini service temporarily unavailable. "
                f"Reason: {self._init_error or 'unknown'}. "
                f"Using local threat intelligence as backup."
            )
        else:
            error_msg = (
                f"Unable to connect to Gemini AI after {len(self.RETRY_DELAYS)} retry attempts. "
                f"Retrying analysis... Error: {self._last_error or 'request failed'}."
            )

        return {
            "analysis": "\n".join(lines),
            "mitre": mitre,
            "score": score,
            "event_count": len(events),
            "provider": "local-fallback",
            "model": "trinetra-algorithm",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error_msg,
            "status": self._status_detail,
            "fallback_reason": self._init_error if not self._available else self._last_error,
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
            "error": (
                f"Gemini service temporarily unavailable. "
                f"Using local threat intelligence as backup. "
                f"Reason: {self._init_error or self._last_error or 'unknown'}."
            ),
            "status": self._status_detail,
        }
