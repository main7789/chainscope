"""
logger.py
────────────────────────────────────────
Purpose : Central logging system for the project.
Imported: By all other project files.
────────────────────────────────────────
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from rich.logging import RichHandler

# ── Create logs directory ──
LOGS_DIR = Path("logs")
LOGS_DIR.mkdir(exist_ok=True)

LOG_FILE = LOGS_DIR / f"chainscope_{datetime.now().strftime('%Y-%m-%d')}.log"


def get_logger(name: str) -> logging.Logger:
    """
    Creates a ready-to-use logger instance.

    name : Name of the module requesting the logger
           (appears in messages to identify the source).
    """

    logger = logging.getLogger(name)

    # If logger is already configured — do not reset it
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)

    # ── Console Handler (Visible output) ──
    console_handler = RichHandler(
        rich_tracebacks=True,
        show_path=False,
        markup=True,
    )
    console_handler.setLevel(logging.INFO)

    # ── File Handler (Debug logs) ──
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