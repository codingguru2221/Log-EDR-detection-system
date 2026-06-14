"""
Gemini Response Cache
---------------------
Persistent file-based cache that stores Gemini API responses locally.
If similar incidents occur, the cached analysis is reused instead of
making a new API call, significantly reducing token consumption.

Cache key generation: hash of (sorted event_types + severity + score bucket)
TTL: Configurable via GEMINI_CACHE_TTL env var (default: 3600s / 1 hour)
Storage: backend/.cache/gemini_cache.json
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path


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


class GeminiCache:
    """Persistent file-based cache for Gemini API responses.

    Thread-safe. Automatically expires entries based on TTL.
    Supports exact match and fuzzy similarity matching.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._ttl: float = float(_get_env("GEMINI_CACHE_TTL", "3600"))
        self._cache_dir = Path(__file__).resolve().parent.parent / ".cache"
        self._cache_file = self._cache_dir / "gemini_cache.json"
        self._data: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        """Load cache from disk."""
        try:
            if self._cache_file.exists():
                with open(self._cache_file, "r", encoding="utf-8") as f:
                    self._data = json.load(f)
                # Prune expired entries on load
                self._prune_expired()
        except (json.JSONDecodeError, OSError, TypeError):
            self._data = {}

    def _save(self) -> None:
        """Save cache to disk."""
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except OSError:
            pass  # Cache persistence is best-effort

    def _prune_expired(self) -> None:
        """Remove expired entries from cache."""
        now = time.time()
        expired = [
            key for key, entry in self._data.items()
            if now - entry.get("timestamp", 0) > self._ttl
        ]
        for key in expired:
            del self._data[key]

    @staticmethod
    def generate_key(events: list[dict], score: int) -> str:
        """Generate a deterministic cache key from events and score.

        Key is based on: sorted event types + severity bucket + score bucket.
        This ensures similar incidents hit the same cache entry.
        """
        event_types = sorted(set(e.get("event_type", "unknown") for e in events[:50]))
        score_bucket = (score // 10) * 10  # Round to nearest 10
        severity = "critical" if score >= 80 else "high" if score >= 50 else "medium" if score >= 20 else "low"

        key_data = f"{','.join(event_types)}|{severity}|{score_bucket}"
        return hashlib.sha256(key_data.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def generate_similarity_signature(events: list[dict], score: int) -> set:
        """Generate a set of features for similarity matching."""
        event_types = set(e.get("event_type", "unknown") for e in events[:50])
        score_bucket = (score // 20) * 20  # Coarser bucketing for similarity
        event_types.add(f"score:{score_bucket}")
        return event_types

    def get(self, key: str) -> dict | None:
        """Retrieve a cached response by exact key.

        Returns None if not found or expired.
        """
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None

            # Check TTL
            if time.time() - entry.get("timestamp", 0) > self._ttl:
                del self._data[key]
                return None

            return entry.get("data")

    def set(self, key: str, data: dict) -> None:
        """Store a response in the cache."""
        with self._lock:
            self._data[key] = {
                "data": data,
                "timestamp": time.time(),
                "similarity": list(data.get("_similarity_sig", [])),
            }
            # Remove internal similarity sig from stored data
            if "_similarity_sig" in self._data[key]["data"]:
                del self._data[key]["data"]["_similarity_sig"]
            self._save()

    def find_similar(self, events: list[dict], score: int, threshold: float = 0.6) -> dict | None:
        """Find a cached response for a similar incident.

        Uses Jaccard similarity on event type sets. Returns the best
        match if similarity exceeds threshold, or None.
        """
        query_sig = self.generate_similarity_signature(events, score)

        with self._lock:
            now = time.time()
            best_match = None
            best_similarity = 0.0

            for key, entry in self._data.items():
                # Skip expired
                if now - entry.get("timestamp", 0) > self._ttl:
                    continue

                cached_sig = set(entry.get("similarity", []))
                if not cached_sig:
                    continue

                # Jaccard similarity
                intersection = len(query_sig & cached_sig)
                union = len(query_sig | cached_sig)
                similarity = intersection / union if union > 0 else 0.0

                if similarity > best_similarity and similarity >= threshold:
                    best_similarity = similarity
                    best_match = entry.get("data")

            return best_match

    def is_valid(self, key: str) -> bool:
        """Check if a cache entry exists and is not expired."""
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return False
            return time.time() - entry.get("timestamp", 0) <= self._ttl

    def clear(self) -> None:
        """Clear all cache entries."""
        with self._lock:
            self._data = {}
            self._save()

    def stats(self) -> dict:
        """Return cache statistics."""
        with self._lock:
            now = time.time()
            active = sum(
                1 for entry in self._data.values()
                if now - entry.get("timestamp", 0) <= self._ttl
            )
            return {
                "total_entries": len(self._data),
                "active_entries": active,
                "expired_entries": len(self._data) - active,
                "ttl_seconds": self._ttl,
                "cache_file": str(self._cache_file),
            }
