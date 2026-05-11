"""
cache.py
────────────────────────────────────────
الغرض  : حفظ نتائج الطلبات مؤقتاً
          لتجنب تكرار طلبات API
مدة    : 5 دقائق لكل نتيجة محفوظة
────────────────────────────────────────
"""

import json
import hashlib
import time
from pathlib import Path
from typing import Any, Optional
from logger import get_logger

logger = get_logger("cache")

# ── الإعدادات ──
CACHE_DIR            = Path("data") / "cache"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_EXPIRY_SECONDS = 300


class CacheManager:
    """
    يُدير حفظ واسترجاع نتائج API
    كل نتيجة = ملف JSON منفصل بمدة صلاحية
    """

    def __init__(self, expiry: int = CACHE_EXPIRY_SECONDS):
        self.expiry    = expiry
        self.cache_dir = CACHE_DIR
        logger.debug("تم تهيئة الكاش — مدة الصلاحية: %d ثانية", expiry)


    def _make_key(self, identifier: str) -> str:
        """يحوّل أي نص لاسم ملف آمن"""
        return hashlib.md5(identifier.encode()).hexdigest()


    def get(self, identifier: str) -> Optional[Any]:
        """يسترجع قيمة محفوظة — يرجع None إذا غير موجودة أو منتهية"""

        cache_file = self.cache_dir / f"{self._make_key(identifier)}.json"

        if not cache_file.exists():
            return None

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                cached_data = json.load(f)

            age = time.time() - cached_data["saved_at"]

            if age > self.expiry:
                cache_file.unlink()
                logger.debug("انتهت صلاحية الكاش: %s", identifier[:20])
                return None

            logger.debug("كاش صالح (%.0f ث): %s", age, identifier[:20])
            return cached_data["value"]

        except (json.JSONDecodeError, KeyError):
            cache_file.unlink(missing_ok=True)
            return None


    def set(self, identifier: str, value: Any) -> None:
        """يحفظ قيمة في الكاش مع وقت الحفظ"""

        cache_file = self.cache_dir / f"{self._make_key(identifier)}.json"

        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(
                    {"saved_at": time.time(), "identifier": identifier, "value": value},
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
            logger.debug("تم حفظ الكاش: %s", identifier[:20])

        except OSError as e:
            logger.error("فشل حفظ الكاش: %s", str(e))


    def clear_all(self) -> int:
        """يحذف كل ملفات الكاش — يرجع عدد الملفات المحذوفة"""
        deleted = 0
        for f in self.cache_dir.glob("*.json"):
            f.unlink()
            deleted += 1
        logger.info("تم مسح الكاش — حُذف %d ملف", deleted)
        return deleted