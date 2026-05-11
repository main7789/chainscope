"""
logger.py
────────────────────────────────────────
الغرض  : نظام تسجيل مركزي لكل أحداث المشروع
يُستورد: في كل ملفات المشروع الأخرى
────────────────────────────────────────
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.logging import RichHandler

# ── إنشاء مجلد السجلات ──
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

LOG_FILE = LOGS_DIR / f"chainscope_{datetime.now().strftime('%Y-%m-%d')}.log"


def get_logger(name: str) -> logging.Logger:
    """
    تُنشئ مسجّلاً جاهزاً للاستخدام

    name : اسم الملف الذي يطلب المسجّل
           يظهر في كل رسالة لتحديد مصدرها
    """

    logger = logging.getLogger(name)

    # إذا المسجّل مُعدّ مسبقاً — لا نُعيد ضبطه
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── قناة الشاشة ──
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_path=False,
        markup=True,
    )
    console_handler.setLevel(logging.INFO)

    # ── قناة الملف ──
    file_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)

    file_formatter = logging.Formatter(
        fmt="[%(asctime)s] %(levelname)-8s | %(name)-12s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger