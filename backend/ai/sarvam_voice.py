"""
Trinetra Sentinel Voice Module
-------------------------------
Unified multilingual voice notification system with intelligent provider routing:

- Hindi & English: Sarvam AI (primary), Edge TTS (fallback)
- Regional Indian languages: Google Cloud TTS -> Edge TTS -> Browser TTS
- Fallback chain: Primary -> Edge TTS -> Sarvam AI -> Browser-native TTS

Supported languages: English, Hindi, Marathi, Gujarati, Telugu, Tamil,
Kannada, Malayalam, Bengali, Punjabi, Odia, Assamese.

Voice generation never crashes — all exceptions return browser-fallback.
"""

from __future__ import annotations

import base64
import io
import logging
import os
from datetime import datetime, timezone

from .google_tts import GoogleCloudTTS, GOOGLE_TTS_LANGUAGES
from .edge_tts_provider import EdgeTTSProvider

logger = logging.getLogger(__name__)


def _get_env(key: str, default: str = "") -> str:
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


try:
    import requests as _requests
    _HAS_REQUESTS = True
except ImportError:
    _requests = None
    _HAS_REQUESTS = False


# ── Language codes for Sarvam AI (only en + hi now) ──
SARVAM_LANGUAGES = {
    "en": "en-IN",
    "hi": "hi-IN",
}

# Languages handled by Sarvam AI directly
SARVAM_ROUTED_LANGUAGES = {"en", "hi"}

# ── Pre-built translations for common alerts ──
ALERT_TRANSLATIONS = {
    "hi": {
        "critical_threat": "Gambhir suraksha khatra detect hua hai. Turant investigation karne ki salah di jaati hai.",
        "high_threat": "Uchch star ka suraksha khatra detect hua hai. Kripya alert ki samiksha karein.",
        "medium_threat": "Madhyam star ka suraksha alert detect hua hai. Nigraani ki salah di jaati hai.",
        "low_threat": "Nimn star ka suraksha event detect hua hai. Koi turant karvayi ki zarurat nahi.",
        "usb_detected": "USB device detect hui hai. Kripya scan karein pehle upyog karne se.",
        "ransomware": "Ransomware jaisi gatividhi detect hui hai. Turant network se disconnect karein.",
        "failed_login": "Bahut se asafal login prayas detect hue hain. Brute force attack sambhav hai.",
        "system_normal": "System surakshit hai. Koi khatra detect nahi hua.",
        "incident_generated": "Incident report taiyar ki gayi hai. Kripya review karein.",
    },
    "te": {
        "critical_threat": "Tivramaina bhadratha muppu gurthinchabadindi. Dayachesi ventane parishilinchandi.",
        "high_threat": "High level bhadratha muppu gurthinchabadindi. Dayachesi alert ni parishilinchandi.",
        "medium_threat": "Medium level bhadratha alert gurthinchabadindi. Paryaveekshana salah isthunnamu.",
        "low_threat": "Low level bhadratha event gurthinchabadindi. Ventane charya avasaram ledu.",
        "usb_detected": "USB device gurthinchabadindi. Vadakamundu scan cheyandi.",
        "ransomware": "Ransomware laanti karyam gurthinchabadindi. Ventane network nunchi disconnect cheyandi.",
        "failed_login": "Chala failed login prayatnaalu gurthinchabaadayaayi. Brute force attack ayye avakaasam undi.",
        "system_normal": "System surakshitamga undi. Ee muppu ledu.",
        "incident_generated": "Incident report sidham chesamu. Dayachesi parishilinchandi.",
    },
    "mr": {
        "critical_threat": "गंभीर सुरक्षा धोका आढळला आहे. तात्काळ तपासणी करणे गरजेचे आहे.",
        "high_threat": "उच्च स्तराचा सुरक्षा धोका आढळला आहे. कृपया अलर्टचे पुनरावलोकन करा.",
        "medium_threat": "मध्यम स्तराचा सुरक्षा अलर्ट आढळला आहे. निरीक्षण करणे गरजेचे आहे.",
        "low_threat": "कमी स्तराचा सुरक्षा इव्हेंट आढळला आहे. तात्काळ कारवाईची गरज नाही.",
        "usb_detected": "USB डिव्हाइस आढळले आहे. कृपया वापरण्यापूर्वी स्कॅन करा.",
        "ransomware": "रॅन्समवेअर सारखी क्रिया आढळली आहे. तात्काळ नेटवर्कमधून डिस्कनेक्ट करा.",
        "failed_login": "खूप सारे अयशस्वी लॉगिन प्रयत्न आढळले आहेत. ब्रूट फोर्स हल्ला शक्य आहे.",
        "system_normal": "सिस्टम सुरक्षित आहे. कोणताही धोका आढळला नाही.",
        "incident_generated": "घटना अहवाल तयार आहे. कृपया पुनरावलोकन करा.",
    },
    "gu": {
        "critical_threat": "ગંભીર સુરક્ષા ખતરો ડિટેક્ટ થયો છે. તાત્કાલિક તપાસ કરવી જરૂરી છે.",
        "high_threat": "ઉચ્ચ સ્તરનો સુરક્ષા ખતરો ડિટેક્ટ થયો છે. કૃપા કરીને અલર્ટનું સમીક્ષા કરો.",
        "medium_threat": "મધ્યમ સ્તરનો સુરક્ષા અલર્ટ ડિટેક્ટ થયો છે. નિરીક્ષણ કરવું જરૂરી છે.",
        "low_threat": "નીચા સ્તરનો સુરક્ષા ઇવેન્ટ ડિટેક્ટ થયો છે. કોઈ તાત્કાલિક કાર્યવાહીની જરૂર નથી.",
        "usb_detected": "USB ડિવાઇસ ડિટેક્ટ થયું છે. કૃપા કરીને વાપરતા પહેલા સ્કેન કરો.",
        "ransomware": "રેન્સમવેર જેવી પ્રવૃત્તિ ડિટેક્ટ થઈ છે. તાત્કાલિક નેટવર્કથી ડિસ્કનેક્ટ કરો.",
        "failed_login": "ઘણા બધા ફેલ્ડ લોગિન પ્રયત્નો ડિટેક્ટ થયા છે. બ્રૂટ ફોર્સ હુમલો શક્ય છે.",
        "system_normal": "સિસ્ટમ સુરક્ષિત છે. કોઈ ખતરો ડિટેક્ટ થયો નથી.",
        "incident_generated": "ઘટના રિપોર્ટ તૈયાર છે. કૃપા કરીને સમીક્ષા કરો.",
    },
    "ta": {
        "critical_threat": "Aantraamanan paathukappu aaravili kandaariyappattullath. Uyarntha vidhaaranai seiyyavum.",
        "high_threat": "Uyarvaana paathukappu aaravili kandaariyappattullath. Alert-ai samikshaikkavum.",
        "medium_threat": "Madhiyamaana paathukappu alert kandaariyappattullath. Kaanippu thevai.",
        "low_threat": "Kulainthaana paathukappu nighazhvu kandaariyappattullath. Udane ethuvum seiyya thevaiyilla.",
        "usb_detected": "USB saadhanam kandaariyappattullath. Payanpaduthum mun scan seiyyavum.",
        "ransomware": "Ransomware polana seyal kandaariyappattullath. Udane network-lerunthu thuindikkavum.",
        "failed_login": "Palaiyaana login tholvi muyarchigal kandaariyappattullana. Brute force thakkudiyaaga irukkalaam.",
        "system_normal": "Kaanippu paathukaappaga ullath. Aaravili kandaariyappadavillai.",
        "incident_generated": "Sambhava aricai taiyyaagi ullath. Mnilaiyil parvvaikkavum.",
    },
    "kn": {
        "critical_threat": "Gambhira bhadratha eddu kaanabahudagide. Tumba bega parikshisi.",
        "high_threat": "Hecchu bhadratha eddu kaanabahudagide. Dayavittu alert parikshisi.",
        "medium_threat": "Madhyama bhadratha alert kaanabahudagide. Nirikshana maadi.",
        "low_threat": "Kannada bhadratha ghatane kaanabahudagide. Yavude kriya astheerva illa.",
        "usb_detected": "USB device kaanabahudagide. Upayogakkintle scan maadi.",
        "ransomware": "Ransomware tara charche kaanabahudagide. Tumba bega network inda disconnect maadi.",
        "failed_login": "Tumba failed login prayatnagalu kaanabahudagive. Brute force attack aagabahudu.",
        "system_normal": "System surakshitavaagide. Yavude eddu kaanabahudagilla.",
        "incident_generated": "Incident report taiyaragide. Dayavittu review maadi.",
    },
    "ml": {
        "critical_threat": "Gambheera suraksha bhishani kandethi. Udan thanne parikshanam nadathuka.",
        "high_threat": "Uyarndha suraksha bhishani kandethi. Alert parikshikkuka.",
        "medium_threat": "Madhyama suraksha alert kandethi. Nireekshanam aavashyamanu.",
        "low_threat": "Nimna suraksha sambhavam kandethi. Udan action aavashyamilla.",
        "usb_detected": "USB upakaranam kandethi. Upayogikkunnathinu munp scan cheyyuka.",
        "ransomware": "Ransomware pole ulla pravarthanam kandethi. Udan networkil ninnu disconnect cheyyuka.",
        "failed_login": "Valare failed login shramangal kandethi. Brute force attack aakaam.",
        "system_normal": "System surakshithamanu. Bhishani kandethiyilla.",
        "incident_generated": "Incident report thayaaraayi. Review cheyyuka.",
    },
    "bn": {
        "critical_threat": "Gombhir nirapatta jhunki dhora poreche. Druto toronto jobostha janch korun.",
        "high_threat": "Uchcho starer nirapatta jhunki dhora poreche. Alert porikkha korun.",
        "medium_threat": "Modhyom starer nirapatta alert dhora poreche. Nirikhan dorkar.",
        "low_threat": "Nimno starer nirapatta ghotona dhora poreche. Kono druto podokkhep dorkar nei.",
        "usb_detected": "USB device dhora poreche. Beboharer age scan korun.",
        "ransomware": "Ransomware er moto krom dhora poreche. Druto network theke disconnect korun.",
        "failed_login": "Onek gulo failed login chesta dhora poreche. Brute force attack hote pare.",
        "system_normal": "System nirapod ache. Kono jhunki dhora poreni.",
        "incident_generated": "Incident report toiri kora hoyeche. Review korun.",
    },
    "pa": {
        "critical_threat": "Gambhir surakhya khatra paya gya hai. Turant jaanch karni chahidi hai.",
        "high_threat": "Uch star da surakhya khatra paya gya hai. Kirpa karke alert da review karo.",
        "medium_threat": "Madham star da surakhya alert paya gya hai. Nigrani karni chahidi hai.",
        "low_threat": "Nivi star di surakhya ghatna payi gayi hai. Koi turant karwai di lorh nahin.",
        "usb_detected": "USB device paya gya hai. Varton ton pehlan scan karo.",
        "ransomware": "Ransomware vargi gatividhi payi gayi hai. Turant network ton disconnect karo.",
        "failed_login": "Bahut sare asafal login yatan paye gaye han. Brute force attack sambhav hai.",
        "system_normal": "System surakhya hai. Koi khatra nahin paya gya.",
        "incident_generated": "Incident report tayyar hai. Review karo.",
    },
    "or": {
        "critical_threat": "Gambhira surakhya khatra chinhi heba. Sighra pariksha karantu.",
        "high_threat": "Uchcha starara surakhya khatra chinhi heba. Alert pariksha karantu.",
        "medium_threat": "Madhyama starara surakhya alert chinhi heba. Nirikshana darakara.",
        "low_threat": "Nimna starara surakhya ghatana chinhi heba. Kono sighra karjya darakara nahin.",
        "usb_detected": "USB device chinhi heba. Byabahara purbaru scan karantu.",
        "ransomware": "Ransomware bhali karjya chinhi heba. Sighra network ru disconnect karantu.",
        "failed_login": "Bahutagudi asafal login chesta chinhi heba. Brute force attack hoi pare.",
        "system_normal": "System surakhya ache. Kono khatra chinhi heba nahin.",
        "incident_generated": "Incident report prastuta ache. Review karantu.",
    },
    "as": {
        "critical_threat": "Gombhir surokkha bhoy dhora porise. Turante parikkha korok.",
        "high_threat": "Uchcha storor surokkha bhoy dhora porise. Alert porikkha korok.",
        "medium_threat": "Modhyom storor surokkha alert dhora porise. Nirikhan dorkar.",
        "low_threat": "Nimno storor surokkha ghotona dhora porise. Kono turonto podokhep dorkar nai.",
        "usb_detected": "USB device dhora porise. Byaboharor age scan korok.",
        "ransomware": "Ransomware r dore karjya dhora porise. Turante network or pora disconnect korok.",
        "failed_login": "Bahu asafal login chesta dhora porise. Brute force attack hobo pare.",
        "system_normal": "System surokkhit ase. Kono bhoy dhora pora nai.",
        "incident_generated": "Incident report prostut ase. Review korok.",
    },
}

# ── Sarvam AI TTS API endpoint ──
SARVAM_TTS_URL = "https://api.sarvam.ai/text-to-speech"


class SarvamVoiceModule:
    """Multilingual voice notification generator with intelligent provider routing.

    Voice routing:
      - en, hi -> Sarvam AI (primary), Edge TTS (fallback)
      - Regional languages -> Google Cloud TTS -> Edge TTS -> Browser TTS

    Fallback chain (for all languages):
      1. Primary provider (Sarvam or Google Cloud based on language)
      2. Edge TTS (free Microsoft Neural voices, all Indian languages)
      3. Sarvam AI (secondary fallback)
      4. Browser-native speech synthesis (last resort)
    """

    def __init__(self):
        self._api_key = _get_env("SARVAM_API_KEY")
        self._sarvam_available = _HAS_REQUESTS and bool(self._api_key)
        self._default_voice = _get_env("SARVAM_DEFAULT_VOICE", "anushka")
        self._google_tts = GoogleCloudTTS()
        self._edge_tts = EdgeTTSProvider()

    @property
    def available(self) -> bool:
        """True if at least one TTS provider is configured."""
        return self._sarvam_available or self._google_tts.available or self._edge_tts.available

    @property
    def google_tts(self) -> GoogleCloudTTS:
        """Access the Google Cloud TTS sub-module."""
        return self._google_tts

    def _route_language(self, language: str) -> str:
        """Determine which provider to use for a given language.

        Returns: "sarvam" or "google"
        """
        if language in SARVAM_ROUTED_LANGUAGES:
            return "sarvam"
        return "google"

    def translate_alert(self, alert: dict, language: str = "en") -> str:
        """Convert an alert to a translated text message."""
        if language == "en":
            severity = alert.get("severity", "low")
            title = alert.get("title", "Security event")
            summary = alert.get("summary", "")[:120]
            return f"{severity.upper()} alert: {title}. {summary}"

        translations = ALERT_TRANSLATIONS.get(language, ALERT_TRANSLATIONS["hi"])
        severity = alert.get("severity", "low")
        event_type = alert.get("event_type", "")

        if event_type == "ransomware_activity":
            return translations["ransomware"]
        if event_type in ("failed_login", "account_lockout"):
            return translations["failed_login"]
        if "usb" in event_type:
            return translations["usb_detected"]

        if severity == "critical":
            return translations["critical_threat"]
        if severity == "high":
            return translations["high_threat"]
        if severity == "medium":
            return translations["medium_threat"]
        return translations["low_threat"]

    def translate_analysis(self, analysis_text: str, language: str = "en") -> str:
        """Create a short voice-friendly summary from a full Gemini analysis.

        Strips markdown, extracts the most important sentences (Executive Summary
        + first bullet of Technical Analysis), and keeps the result under ~200 words
        so TTS produces clear, natural audio.
        """
        import re

        if not analysis_text:
            return "No analysis available."

        # ── Step 1: Strip all markdown ──
        clean = analysis_text
        clean = re.sub(r"#{1,6}\s*", "", clean)
        clean = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean)
        clean = re.sub(r"^\s*[-*+]\s+", "", clean, flags=re.MULTILINE)
        clean = re.sub(r"^\s*\d+\.\s+", "", clean, flags=re.MULTILINE)

        # ── Step 1b: Remove known section titles ──
        section_titles = [
            "Executive Summary", "Technical Analysis", "Potential Impact",
            "MITRE ATT&CK Coverage", "Recommended Actions", "Conclusion",
            "Incident Overview", "Timeline Summary", "Risk Assessment",
            "MITRE ATT&CK References", "Recommended Mitigation Steps",
        ]
        for title in section_titles:
            clean = re.sub(re.escape(title), "", clean, flags=re.IGNORECASE)

        clean = re.sub(r"\s+", " ", clean).strip()

        # ── Step 2: Split into sentences ──
        clean = re.sub(r"\.{2,}", ".", clean)
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", clean) if len(s.strip()) > 10]

        # ── Step 3: Prioritise Executive Summary sentences ──
        priority = sentences[:4]

        # ── Step 4: Cap at ~180 words ──
        words, result = 0, []
        for s in priority:
            wc = len(s.split())
            if words + wc > 180:
                break
            result.append(s)
            words += wc

        short_summary = " ".join(s.rstrip(".") for s in result).rstrip(". ") + "."

        # ── Step 5: For non-English, translate the short summary ──
        if language == "en":
            return short_summary

        translations = ALERT_TRANSLATIONS.get(language, ALERT_TRANSLATIONS["hi"])
        lower = analysis_text.lower()
        if "critical" in lower or "ransomware" in lower:
            return translations["critical_threat"]
        if "high" in lower:
            return translations["high_threat"]
        if "usb" in lower:
            return translations["usb_detected"]
        if "failed login" in lower or "brute force" in lower:
            return translations["failed_login"]
        return translations["system_normal"]

    def synthesize_speech(self, text: str, language: str = "en") -> dict:
        """Generate speech audio with intelligent multi-provider routing.

        Routing:
          - en, hi -> Sarvam AI -> Edge TTS -> browser
          - Regional languages -> Google Cloud TTS -> Edge TTS -> browser

        Returns:
            dict with:
              - audio_base64: base64-encoded audio
              - format: audio format
              - language: language code
              - text: the text spoken
              - provider: "sarvam", "google-cloud-tts", "edge-tts", or "browser-fallback"
              - error: error message if failed
        """
        logger.info(f"[TTS] Request: language={language}, text_length={len(text)}, text_preview={text[:80]}")

        try:
            provider = self._route_language(language)

            if provider == "sarvam":
                # ── en, hi routing: Sarvam -> Edge TTS -> Browser ──
                result = self._sarvam_synthesize(text, language)
                if result.get("audio_base64"):
                    logger.info(f"[TTS] SUCCESS via Sarvam AI for {language}")
                    return result

                # Fallback: Edge TTS (free Microsoft Neural voices)
                if self._edge_tts.available and self._edge_tts.is_supported(language):
                    logger.info(f"[TTS] Sarvam failed for {language}, falling back to Edge TTS")
                    edge_result = self._edge_tts.synthesize_speech(text, language)
                    if edge_result.get("audio_base64"):
                        logger.info(f"[TTS] SUCCESS via Edge TTS for {language}")
                        return edge_result

                return result  # browser-fallback

            else:
                # ── Regional language routing: Google Cloud -> Edge TTS -> Browser ──
                # Primary: Google Cloud TTS
                result = self._google_tts.synthesize_speech(text, language)
                if result.get("audio_base64"):
                    logger.info(f"[TTS] SUCCESS via Google Cloud TTS for {language}")
                    return result

                # Secondary: Edge TTS (free, high quality Neural voices)
                if self._edge_tts.available and self._edge_tts.is_supported(language):
                    logger.info(f"[TTS] Google Cloud unavailable for {language}, falling back to Edge TTS")
                    edge_result = self._edge_tts.synthesize_speech(text, language)
                    if edge_result.get("audio_base64"):
                        logger.info(f"[TTS] SUCCESS via Edge TTS for {language}")
                        return edge_result

                # Tertiary fallback: Sarvam AI (may work for some languages)
                if self._sarvam_available and language in SARVAM_LANGUAGES:
                    logger.info(f"[TTS] Edge TTS failed for {language}, trying Sarvam AI")
                    sarvam_result = self._sarvam_synthesize(text, language)
                    if sarvam_result.get("audio_base64"):
                        logger.info(f"[TTS] SUCCESS via Sarvam AI for {language}")
                        return sarvam_result

                # Last resort: browser fallback
                logger.warning(f"[TTS] All providers failed for {language}, using browser fallback")
                return self._browser_fallback(text, language)

        except Exception as exc:
            # Voice generation must never crash
            logger.error(f"[TTS] Exception in synthesize_speech for {language}: {exc}")
            return self._browser_fallback(text, language, error=str(exc))

    def _sarvam_synthesize(self, text: str, language: str = "en") -> dict:
        """Call Sarvam AI TTS API directly."""
        lang_code = SARVAM_LANGUAGES.get(language, "en-IN")

        if not self._sarvam_available:
            return {
                "audio_base64": None,
                "format": "browser-fallback",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "browser-fallback",
                "error": "Sarvam API not configured — use browser speech synthesis instead",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        try:
            headers = {
                "api-subscription-key": self._api_key,
                "Content-Type": "application/json",
            }
            payload = {
                "inputs": [text],
                "target_language_code": lang_code,
                "speaker": self._default_voice,
            }
            response = _requests.post(
                SARVAM_TTS_URL,
                json=payload,
                headers=headers,
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json()
                audio_b64 = data.get("audios", [None])[0] if isinstance(data, dict) else None
                if audio_b64:
                    return {
                        "audio_base64": audio_b64,
                        "format": "wav",
                        "language": language,
                        "lang_code": lang_code,
                        "text": text,
                        "provider": "sarvam",
                        "error": None,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

            return {
                "audio_base64": None,
                "format": "browser-fallback",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "browser-fallback",
                "error": f"Sarvam API returned status {response.status_code}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            return {
                "audio_base64": None,
                "format": "browser-fallback",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "browser-fallback",
                "error": f"Sarvam API error: {exc}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def _browser_fallback(self, text: str, language: str = "en", error: str | None = None) -> dict:
        """Return a browser-fallback response for client-side TTS."""
        lang_config = GOOGLE_TTS_LANGUAGES.get(language, {})
        lang_code = lang_config.get("language_code", SARVAM_LANGUAGES.get(language, f"{language}-IN"))
        return {
            "audio_base64": None,
            "format": "browser-fallback",
            "language": language,
            "lang_code": lang_code,
            "text": text,
            "provider": "browser-fallback",
            "error": error or "Using browser speech synthesis as fallback",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def speak_alert(self, alert: dict, language: str = "en") -> dict:
        """Full pipeline: translate alert -> synthesize speech."""
        text = self.translate_alert(alert, language)
        return self.synthesize_speech(text, language)

    def speak_analysis(self, analysis_text: str, language: str = "en") -> dict:
        """Full pipeline: summarize analysis -> synthesize speech."""
        text = self.translate_analysis(analysis_text, language)
        return self.synthesize_speech(text, language)

    def generate_voice_report(self, report_text: str, language: str = "en") -> dict:
        """Generate a multilingual voice report from a local analytics report.

        Pipeline:
          1. Extract executive summary from report (English)
          2. Translate if non-English
          3. Route through appropriate TTS provider

        Args:
            report_text: The local analytics report (English markdown)
            language: Target language code

        Returns:
            Speech synthesis result dict
        """
        import re

        if not report_text:
            return self.synthesize_speech("No report available.", language)

        # Extract a concise executive summary for voice (under 150 words)
        clean = report_text
        clean = re.sub(r"#{1,6}\s*", "", clean)
        clean = re.sub(r"\*{1,2}(.+?)\*{1,2}", r"\1", clean)
        clean = re.sub(r"`{1,3}[^`]*`{1,3}", "", clean)
        clean = re.sub(r"\[([^\]]+)\]\([^\)]+\)", r"\1", clean)
        clean = re.sub(r"^\s*[-*+]\s+", "", clean, flags=re.MULTILINE)
        clean = re.sub(r"^\s*\d+\.\s+", "", clean, flags=re.MULTILINE)

        # Remove section titles
        for title in [
            "Executive Summary", "Event Timeline", "Risk Assessment",
            "Attack Chain Analysis", "Recommended Actions", "Incident Report",
            "Trinetra Sentinel", "Conclusion",
        ]:
            clean = re.sub(re.escape(title), "", clean, flags=re.IGNORECASE)

        clean = re.sub(r"\s+", " ", clean).strip()

        # Extract first 3-4 meaningful sentences
        sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+", clean) if len(s.strip()) > 10]
        priority = sentences[:4]

        words, result = 0, []
        for s in priority:
            wc = len(s.split())
            if words + wc > 150:
                break
            result.append(s)
            words += wc

        voice_text = " ".join(s.rstrip(".") for s in result).rstrip(". ") + "."

        # For non-English, use translation layer
        if language != "en":
            translations = ALERT_TRANSLATIONS.get(language, ALERT_TRANSLATIONS.get("hi", {}))
            lower = report_text.lower()
            if "critical" in lower or "ransomware" in lower:
                voice_text = translations.get("critical_threat", voice_text)
            elif "high" in lower:
                voice_text = translations.get("high_threat", voice_text)
            elif "failed login" in lower or "brute force" in lower:
                voice_text = translations.get("failed_login", voice_text)
            elif "usb" in lower:
                voice_text = translations.get("usb_detected", voice_text)
            else:
                voice_text = translations.get("system_normal", voice_text)

        return self.synthesize_speech(voice_text, language)

    def get_supported_languages(self) -> list[dict]:
        """Return list of all supported languages for the frontend."""
        languages = [
            {"code": "en", "label": "English", "native": "English"},
            {"code": "hi", "label": "Hindi", "native": "हिन्दी"},
        ]
        # Add all Google Cloud TTS languages
        for code, config in GOOGLE_TTS_LANGUAGES.items():
            if code not in ("en", "hi"):
                languages.append({
                    "code": code,
                    "label": config["label"],
                    "native": config["native"],
                })
        return languages
