"""
Google Cloud Text-to-Speech Module
---------------------------------
Provides high-quality multilingual voice synthesis for Indian regional
languages using Google Cloud TTS API. Used as the primary voice engine
for all languages except Hindi and English (which use Sarvam AI).

Supported languages: Marathi, Gujarati, Telugu, Tamil, Kannada, Malayalam,
Bengali, Punjabi, Odia, Assamese.

Falls back gracefully if the API is unavailable or not configured.
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone


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


# ── Google Cloud TTS SDK import (graceful fallback) ──
try:
    from google.cloud import texttospeech
    _HAS_GOOGLE_TTS = True
except ImportError:
    texttospeech = None
    _HAS_GOOGLE_TTS = False


# ── Language configuration for Google Cloud TTS ──
# Each language maps to: language_code, voice name (Wavenet preferred for quality),
# and SSML gender preference.
GOOGLE_TTS_LANGUAGES: dict[str, dict] = {
    "mr": {
        "language_code": "mr-IN",
        "voice_name": "mr-IN-Wavenet-A",
        "ssml_gender": "FEMALE",
        "label": "Marathi",
        "native": "मराठी",
    },
    "gu": {
        "language_code": "gu-IN",
        "voice_name": "gu-IN-Wavenet-A",
        "ssml_gender": "FEMALE",
        "label": "Gujarati",
        "native": "ગુજરાતી",
    },
    "te": {
        "language_code": "te-IN",
        "voice_name": "te-IN-Standard-A",
        "ssml_gender": "FEMALE",
        "label": "Telugu",
        "native": "తెలుగు",
    },
    "ta": {
        "language_code": "ta-IN",
        "voice_name": "ta-IN-Wavenet-A",
        "ssml_gender": "FEMALE",
        "label": "Tamil",
        "native": "தமிழ்",
    },
    "kn": {
        "language_code": "kn-IN",
        "voice_name": "kn-IN-Standard-A",
        "ssml_gender": "FEMALE",
        "label": "Kannada",
        "native": "ಕನ್ನಡ",
    },
    "ml": {
        "language_code": "ml-IN",
        "voice_name": "ml-IN-Wavenet-A",
        "ssml_gender": "FEMALE",
        "label": "Malayalam",
        "native": "മലയാളം",
    },
    "bn": {
        "language_code": "bn-IN",
        "voice_name": "bn-IN-Wavenet-A",
        "ssml_gender": "FEMALE",
        "label": "Bengali",
        "native": "বাংলা",
    },
    "pa": {
        "language_code": "pa-IN",
        "voice_name": "pa-IN-Standard-A",
        "ssml_gender": "FEMALE",
        "label": "Punjabi",
        "native": "ਪੰਜਾਬੀ",
    },
    "or": {
        "language_code": "or-IN",
        "voice_name": "or-IN-Standard-A",  # Fallback: Standard (Wavenet may not exist)
        "ssml_gender": "FEMALE",
        "label": "Odia",
        "native": "ଓଡ଼ିଆ",
    },
    "as": {
        "language_code": "as-IN",
        "voice_name": "as-IN-Standard-A",
        "ssml_gender": "FEMALE",
        "label": "Assamese",
        "native": "অসমীয়া",
    },
}


class GoogleCloudTTS:
    """Google Cloud Text-to-Speech engine for Indian regional languages.

    Produces audio in the same dict format as SarvamVoiceModule so callers
    can treat both providers interchangeably.
    """

    def __init__(self):
        self._key_path = _get_env("GOOGLE_TTS_KEY")
        self._client = None
        self._available = False
        self._init_error: str | None = None

        if _HAS_GOOGLE_TTS:
            try:
                if self._key_path and os.path.isfile(self._key_path):
                    # Service account JSON file path
                    os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", self._key_path)
                    self._client = texttospeech.TextToSpeechClient()
                    self._available = True
                elif self._key_path:
                    # Key path provided but file not found — try as inline credentials
                    # This handles the case where GOOGLE_APPLICATION_CREDENTIALS is already set
                    self._client = texttospeech.TextToSpeechClient()
                    self._available = True
                else:
                    # Try default credentials (e.g., gcloud auth application-default)
                    try:
                        self._client = texttospeech.TextToSpeechClient()
                        self._available = True
                    except Exception:
                        self._init_error = "GOOGLE_TTS_KEY not set and no default credentials found"
            except Exception as exc:
                self._init_error = f"{type(exc).__name__}: {exc}"
        else:
            self._init_error = "google-cloud-texttospeech package not installed"

    @property
    def available(self) -> bool:
        return self._available

    @property
    def init_error(self) -> str | None:
        return self._init_error

    def is_supported(self, language: str) -> bool:
        """Check if a language is supported by Google Cloud TTS."""
        return language in GOOGLE_TTS_LANGUAGES

    def synthesize_speech(self, text: str, language: str = "mr") -> dict:
        """Generate speech audio using Google Cloud TTS API.

        Returns:
            dict with same format as SarvamVoiceModule.synthesize_speech():
              - audio_base64: base64-encoded MP3 audio
              - format: audio format ("mp3")
              - language: language code
              - lang_code: full locale (e.g., "mr-IN")
              - text: the text spoken
              - provider: "google-cloud-tts" or "google-fallback"
              - error: error message if failed
              - timestamp: ISO timestamp
        """
        lang_config = GOOGLE_TTS_LANGUAGES.get(language)
        if not lang_config:
            return self._error_response(
                text, language, f"Unsupported language: {language}"
            )

        lang_code = lang_config["language_code"]

        if not self._available or not self._client:
            return self._error_response(
                text, language,
                f"Google Cloud TTS not available: {self._init_error or 'not configured'}",
                lang_code=lang_code,
            )

        try:
            synthesis_input = texttospeech.SynthesisInput(text=text)

            voice = texttospeech.VoiceSelectionParams(
                language_code=lang_code,
                name=lang_config["voice_name"],
                ssml_gender=getattr(
                    texttospeech.SsmlVoiceGender,
                    lang_config["ssml_gender"],
                    texttospeech.SsmlVoiceGender.FEMALE,
                ),
            )

            audio_config = texttospeech.AudioConfig(
                audio_encoding=texttospeech.AudioEncoding.MP3,
                speaking_rate=1.0,
                pitch=0.0,
            )

            response = self._client.synthesize_speech(
                input=synthesis_input,
                voice=voice,
                audio_config=audio_config,
            )

            # Encode audio to base64
            audio_b64 = base64.b64encode(response.audio_content).decode("utf-8")

            return {
                "audio_base64": audio_b64,
                "format": "mp3",
                "language": language,
                "lang_code": lang_code,
                "text": text,
                "provider": "google-cloud-tts",
                "error": None,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            return self._error_response(
                text, language,
                f"Google Cloud TTS error: {type(exc).__name__}: {exc}",
                lang_code=lang_code,
            )

    def _error_response(
        self, text: str, language: str, error: str, lang_code: str | None = None
    ) -> dict:
        """Generate a standardized error/fallback response."""
        if lang_code is None:
            lang_config = GOOGLE_TTS_LANGUAGES.get(language, {})
            lang_code = lang_config.get("language_code", f"{language}-IN")

        return {
            "audio_base64": None,
            "format": "browser-fallback",
            "language": language,
            "lang_code": lang_code,
            "text": text,
            "provider": "google-fallback",
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_supported_languages(self) -> list[dict]:
        """Return list of supported languages for the frontend."""
        return [
            {
                "code": code,
                "label": config["label"],
                "native": config["native"],
            }
            for code, config in GOOGLE_TTS_LANGUAGES.items()
        ]
