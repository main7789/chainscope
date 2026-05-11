"""
cache.py
────────────────────────────────────────
Purpose : Temporarily save API results
          to avoid redundant requests.
Duration: 5 minutes (300s) per entry.
────────────────────────────────────────
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional
from logger import get_logger

logger = get_logger("cache")

# ── Configuration ──
CACHE_DIR            = Path("data") / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_EXPIRY_SECONDS = 300


class CacheManager:
    """
   Manages saving and retrieving API results.
   Each result is a separate JSON file with an expiry timestamp.
    """

    def __init__(self, expiry: int = CACHE_EXPIRY_SECONDS):
        self.expiry    = expiry
        self.cache_dir = CACHE_DIR
        logger.debug("Cache initialized — Expiry:  : %d seconds", expiry)


    def _make_key(self, identifier: str) -> str:
        """Converts any string to a safe filename using MD5 hashing"""

        return hashlib.md5(identifier.encode()).hexdigest()


    def get(self, identifier: str) -> Optional[Any]:
        """Retrieves cached value — Returns None if missing or expired"""

        cache_file = self.cache_dir / f"{self._make_key(identifier)}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)

            age = time.time() - cached_data["saved_at"]

            if age > self.expiry:
                cache_file.unlink()
                logger.debug("Cache expired for: %s", identifier[:20])
                return None

            logger.debug("Valid cache hit  (%.0fs ago): %s", age, identifier[:20])
            return cached_data["value"]

        except (json.JSONDecodeError, KeyError):
            cache_file.unlink(missing_ok=True)
            return None


    def set(self, identifier: str, value: Any) -> None:
        """Saves a value in the cache with the current timestamp"""

        cache_file = self.cache_dir / f"{self._make_key(identifier)}.json"

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(
                    {"saved_at": time.time(), "identifier": identifier, "value": value},
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
            logger.debug("Cache saved: %s", identifier[:20])

        except OSError as e:
            logger.error("Failed to save cache: %s", str(e))


    def clear_all(self) -> int:
        """Deletes all cache files — Returns the count of deleted files"""

        deleted = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink()
            deleted += 1
        logger.info("Cache cleared — %d files deleted", deleted)
        return deleted