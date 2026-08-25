"""Structured Application Logging for NetSage AI.

Provides centralized logging configuration respecting NETSAGE_LOG_LEVEL
and ensuring credentials and secrets are never logged.
"""

import logging
import os
import re
from typing import Optional

# Secret sanitization pattern
_SECRET_PATTERN = re.compile(r"(AIzaSy[A-Za-z0-9_-]{10,50}|AQ\.[A-Za-z0-9_-]+)")


class SecretMaskingFilter(logging.Filter):
    """Logging filter that masks accidental credential leaks in log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = _SECRET_PATTERN.sub("[REDACTED_SECRET]", record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (_SECRET_PATTERN.sub("[REDACTED_SECRET]", v) if isinstance(v, str) else v)
                    for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(
                    _SECRET_PATTERN.sub("[REDACTED_SECRET]", a) if isinstance(a, str) else a
                    for a in record.args
                )
        return True


def setup_logging(level_name: Optional[str] = None) -> logging.Logger:
    """Configure root and package-level logging.

    Args:
        level_name: Optional logging level override (e.g. DEBUG, INFO, WARNING).

    Returns:
        Configured Logger instance for netsage.
    """
    lvl_str = (level_name or os.getenv("NETSAGE_LOG_LEVEL", "INFO")).upper().strip()
    log_level = getattr(logging, lvl_str, logging.INFO)

    root_logger = logging.getLogger("netsage")
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers if setup_logging is called multiple times
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(log_level)
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        handler.addFilter(SecretMaskingFilter())
        root_logger.addHandler(handler)

    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Obtain a namespaced child logger under netsage."""
    return logging.getLogger(f"netsage.{name}")
