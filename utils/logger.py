"""
Centralized Structured Logger

Features:
  - JSON-formatted log lines (easily ingested by ELK / CloudWatch / Loki)
  - Per-request correlation_id injected via Flask's g context
  - Log level driven by LOG_LEVEL environment variable (default: INFO)
  - get_logger(name) factory for consistent module-level use

Usage:
    from utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Block added", extra={"block_index": 5})
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Correlation ID helper — Flask-aware, falls back to thread-local
# ---------------------------------------------------------------------------

def _get_correlation_id() -> str:
    """Attempt to read correlation_id from Flask's request context."""
    try:
        from flask import g
        return getattr(g, "correlation_id", "no-ctx")
    except RuntimeError:
        return "no-ctx"
    except ImportError:
        return "no-flask"


# ---------------------------------------------------------------------------
# JSON formatter
# ---------------------------------------------------------------------------

class JSONFormatter(logging.Formatter):
    """
    Produces one JSON object per log line:
    {
        "ts": "2026-02-22T17:58:01.123Z",
        "level": "INFO",
        "module": "blockchain.pbft",
        "correlation_id": "abc-123",
        "message": "...",
        "extra": {...}
    }
    """

    def format(self, record: logging.LogRecord) -> str:
        log_obj: dict[str, Any] = {
            "ts":             datetime.now(timezone.utc).isoformat(),
            "level":          record.levelname,
            "module":         record.name,
            "correlation_id": _get_correlation_id(),
            "message":        record.getMessage(),
        }

        # Attach any extra fields passed via `extra=` or direct attributes
        extra = {}
        skip = {
            "name", "msg", "args", "created", "filename", "funcName",
            "levelname", "levelno", "lineno", "module", "msecs",
            "message", "pathname", "process", "processName",
            "relativeCreated", "stack_info", "thread", "threadName",
            "exc_info", "exc_text",
        }
        for key, val in record.__dict__.items():
            if key not in skip:
                extra[key] = val

        if extra:
            log_obj["extra"] = extra

        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_obj)


# ---------------------------------------------------------------------------
# Logger factory
# ---------------------------------------------------------------------------

_ROOT_LOGGER_NAME = "ssrbc"
_configured       = False


def _configure_root_logger():
    global _configured
    if _configured:
        return

    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level      = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger(_ROOT_LOGGER_NAME)
    root.setLevel(level)

    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        root.addHandler(handler)

    _configured = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a child logger of the root SSRBC logger.

    Args:
        name: Typically __name__ from the calling module.

    Returns:
        logging.Logger instance with JSON output.
    """
    _configure_root_logger()
    # Namespace under root so the root handler is inherited
    return logging.getLogger(f"{_ROOT_LOGGER_NAME}.{name}")
