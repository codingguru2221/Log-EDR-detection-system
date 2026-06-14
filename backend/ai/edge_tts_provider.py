"""
Edge TTS Provider — Free Microsoft Neural Voice Synthesis
-----------------------------------------------------------
Uses Microsoft Edge's online TTS service (edge-tts) for high-quality
multilingual voice synthesis across all Indian languages.

This is a FREE service with no API key required. It provides Neural
voices for Marathi, Gujarati, Telugu, Tamil, Kannada, Malayalam,
Bengali, Hindi, and English (India).

Used as:
  - Primary provider for regional Indian languages (mr, gu, te, ta, kn, ml, bn)
  - Fallback for en/hi when Sarvam AI is unavailable

Voice generation is async — this module provides a sync wrapper.
"""

from __future__ import annotations

import asyncio
import base64
import io
import logging
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# ── Edge TTS import (graceful fallback) ──
try:
    import edge_tts
    _HAS_EDGE_TTS = True
except ImportError:
    edge_tts = None
    _HAS_EDGE_TTS = False

# ── Voice mapping for all supported languages ──
# Each language maps to a list of voices in priority order (female preferred)
EDGE_VOICES: dict[str, list[dict]] = {
    "en": [
        {"name": "en-IN-NeerjaExpressiveNeural", "gender": "Female"},
        {"name": "en-IN-NeerjaNeural", "gender": "Female"},
        {"name": "en-IN-PrabhatNeural", "gender": "Male"},
    ],
    "hi": [
        {"name": "hi-IN-SwaraNeural", "gender": "Female"},
        {"name": "hi-IN-MadhurNeural", "gender": "Male"},
    ],
    "mr": [
        {"name": "mr-IN-AarohiNeural", "gender": "Female"},
        {"name": "mr-IN-ManoharNeural", "gender": "Male"},
    ],
    "gu": [
        {"name": "gu-IN-DhwaniNeural", "gender": "Female"},
        {"name": "gu-IN-NiranjanNeural", "gender": "Male"},
    ],
    "te": [
        {"name": "te-IN-ShrutiNeural", "gender": "Female"},
        {"name": "te-IN-MohanNeural", "gender": "Male"},
    ],
    "ta": [
        {"name": "ta-IN-PallaviNeural", "gender": "Female"},
        {"name": "ta-IN-ValluvarNeural", "gender": "Male"},
    ],
    "kn": [
        {"name": "kn-IN-SapnaNeural", "gender": "Female"},
        {"name": "kn-IN-GaganNeural", "gender": "Male"},
    ],
    "ml": [
        {"name": "ml-IN-SobhanaNeural", "gender": "Female"},
        {"name": "ml-IN-MidhunNeural", "gender": "Male"},
    ],
    "bn": [
        {"name": "bn-IN-TanishaaNeural", "gender": "Female"},
        {"name": "bn-IN-BashkarNeural", "gender": "Male"},
    ],
}

# Language code mapping
EDGE_LANG_CODES: dict[str, str] = {
    "en": "en-IN",
    "hi": "hi-IN",
    "mr": "mr-IN",
    "gu": "gu-IN",
    "te": "te-IN",
    "ta": "ta-IN",
    "kn": "kn-IN",
    "ml": "ml-IN",
    "bn": "bn-IN",
}


class EdgeTTSProvider:
    """Microsoft Edge TTS provider for Indian regional languages.

    Free, no API key required. Uses Neural voices for high quality output.
    Produces audio in MP3 format.
    """

    def __init__(self):
        self._available = _HAS_EDGE_TTS
        if not self._available:
            logger.warning("[EdgeTTS] edge-tts package not installed. Install with: pip install edge-tts")

    @property
    def available(self) -> bool:
        return self._available

    def is_supported(self, language: str) -> bool:
        """Check if a language is supported by Edge TTS."""
        return language in EDGE_VOICES

    def get_voice(self, language: str) -> str | None:
        """Get the primary voice name for a language."""
        voices = EDGE_VOICES.get(language, [])
        return voices[0]["name"] if voices else None

    def synthesize_speech(self, text: str, language: str = "mr") -> dict:
        """Generate speech audio using Edge TTS (sync wrapper).

        Args:
            text: Text to synthesize (should be in native script)
            language: Language code (e.g., 'mr', 'gu', 'ta')

        Returns:
            dict with audio_base64, format, provider, etc.
        """
        if not self._available:
            return self._error_response(text, language, "edge-tts package not installed")

        if not self.is_supported(language):
            return self._error_response(text, language, f"Unsupported language: {language}")

        voice_name = self.get_voice(language)
        lang_code = EDGE_LANG_CODES.get(language, f"{language}-IN")

        start_time = time.time()
        logger.info(
            f"[TTS] Language: {language}, Code: {lang_code}, "
            f"Provider: Edge TTS, Voice: {voice_name}, Text length: {len(text)}"
        )

        try:
            # Run async TTS in a new event loop
            audio_bytes = self._run_async_synth(text, voice_name)

            if audio_bytes and len(audio_bytes) > 100:
                audio_b64 = base64.b64encode(audio_bytes).decode("utf-8")
                elapsed = time.time() - start_time

                logger.info(
                    f"[TTS] Language: {language}, Code: {lang_code}, "
                    f"Provider: Edge TTS, Voice: {voice_name}, "
                    f"Status: Success, Audio Size: {len(audio_bytes)} bytes, "
                    f"Time: {elapsed:.2f}s"
                )

                return {
                    "audio_base64": audio_b64,
                    "format": "mp3",
                    "language": language,
                    "lang_code": lang_code,
                    "text": text,
                    "provider": "edge-tts",
                    "voice": voice_name,
                    "error": None,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            else:
                logger.error(f"[TTS] Edge TTS returned empty audio for {language}")
                return self._error_response(text, language, "Edge TTS returned empty audio")

        except Exception as exc:
            elapsed = time.time() - start_time
            logger.error(
                f"[TTS] Language: {language}, Code: {lang_code}, "
                f"Provider: Edge TTS, Status: Failed, "
                f"Reason: {type(exc).__name__}: {exc}, Time: {elapsed:.2f}s"
            )
            return self._error_response(text, language, f"Edge TTS error: {exc}")

    def _run_async_synth(self, text: str, voice_name: str) -> bytes:
        """Run async edge-tts synthesis in a new event loop."""
        async def _synthesize():
            communicate = edge_tts.Communicate(text, voice_name)
            audio_chunks = []
            async for chunk in communicate.stream():
                if chunk["type"] == "audio":
                    audio_chunks.append(chunk["data"])
            return b"".join(audio_chunks)

        # Create a new event loop to avoid conflicts with existing async code
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(_synthesize())
        finally:
            loop.close()

    def _error_response(self, text: str, language: str, error: str) -> dict:
        """Generate a standardized error response."""
        lang_code = EDGE_LANG_CODES.get(language, f"{language}-IN")
        return {
            "audio_base64": None,
            "format": "browser-fallback",
            "language": language,
            "lang_code": lang_code,
            "text": text,
            "provider": "edge-tts-failed",
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def get_supported_languages(self) -> list[dict]:
        """Return list of supported languages."""
        labels = {
            "en": ("English", "English"),
            "hi": ("Hindi", "हिन्दी"),
            "mr": ("Marathi", "मराठी"),
            "gu": ("Gujarati", "ગુજરાતી"),
            "te": ("Telugu", "తెలుగు"),
            "ta": ("Tamil", "தமிழ்"),
            "kn": ("Kannada", "ಕನ್ನಡ"),
            "ml": ("Malayalam", "മലയാളം"),
            "bn": ("Bengali", "বাংলা"),
        }
        return [
            {"code": code, "label": labels.get(code, (code, code))[0],
             "native": labels.get(code, (code, code))[1]}
            for code in EDGE_VOICES
        ]
