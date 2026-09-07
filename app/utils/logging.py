"""Structured logging configuration.

The logger never records secrets. Callers are responsible for not passing
passwords, private keys or tokens into log messages; helpers in this module
provide a light redaction pass as a second line of defence.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

_LOGGER_NAME = "cis_auditor"

# Patterns that should never reach the log sink even if a caller is careless.
_REDACTION_PATTERNS = [
    re.compile(r"(?i)(password\s*[:=]\s*)(\S+)"),
    re.compile(r"(?i)(secret\s*[:=]\s*)(\S+)"),
    re.compile(r"(?i)(token\s*[:=]\s*)(\S+)"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"),
]


class _RedactingFormatter(logging.Formatter):
    """A formatter that scrubs obvious secrets from every emitted record."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        for pattern in _REDACTION_PATTERNS:
            if pattern.groups >= 2:
                message = pattern.sub(r"\1[REDACTED]", message)
            else:
                message = pattern.sub("[REDACTED]", message)
        return message


def configure_logging(
    level: str = "INFO",
    log_file: Path | None = None,
    quiet: bool = False,
) -> logging.Logger:
    """Configure and return the application logger.

    Args:
        level: One of DEBUG, INFO, WARNING, ERROR.
        log_file: Optional path to also write structured logs to.
        quiet: When True, suppress console output below WARNING.
    """
    logger = logging.getLogger(_LOGGER_NAME)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.handlers.clear()
    logger.propagate = False

    fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    formatter = _RedactingFormatter(fmt, datefmt="%Y-%m-%dT%H:%M:%S%z")

    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(logging.WARNING if quiet else logger.level)
    console.setFormatter(formatter)
    logger.addHandler(console)

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logger.level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger() -> logging.Logger:
    """Return the shared application logger (configured lazily if needed)."""
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        return configure_logging()
    return logger
