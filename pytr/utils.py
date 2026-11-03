#!/usr/bin/env python3

import json
import logging
import os
import re
import sys
import threading

log_level = None
debug_logfile_handler = None
debug_log_filter = None

# Set to a non-empty value to have the websocket traffic written to the debug log.
# Off by default: those messages carry the complete portfolio, every transaction and
# the account holder's personal data, and debug logs end up pasted into bug reports.
ENV_LOG_PAYLOADS = "PYTR_LOG_PAYLOADS"

REDACTED = "[REDACTED]"

# Values shorter than this are never redacted by plain substring replacement. A
# 4-digit PIN would otherwise be blanked inside every amount, ISIN and timestamp that
# happens to contain it, and the pattern of those holes would give the PIN away.
# Short secrets have to stay out of log messages in the first place.
_MIN_SECRET_LENGTH = 8

_secrets: set[str] = set()
_secrets_lock = threading.Lock()

_SECRET_PATTERNS = [
    # JSON fields that carry credentials or session state.
    (
        re.compile(
            r'("(?:pin|password|token|refreshToken|sessionToken|processId|code|phoneNumber)"\s*:\s*")[^"]*(")',
            re.IGNORECASE,
        ),
        rf"\1{REDACTED}\2",
    ),
    # JSON Web Tokens, which is what the Trade Republic session cookies are.
    (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"), REDACTED),
    # Cookie headers and name=value pairs of the cookies that hold the session.
    (
        re.compile(r"((?:tr_session|tr_refresh|tr_claims|aws-waf-token)=)[^;\s'\"]+", re.IGNORECASE),
        rf"\1{REDACTED}",
    ),
]


def log_payloads():
    """Whether websocket payloads may be written to the debug log."""
    return bool(os.environ.get(ENV_LOG_PAYLOADS))


def register_secret(value):
    """Make sure `value` never appears in any log output of pytr.

    Meant for long, high-entropy values: tokens, cookie values, process ids, the
    phone number. See `_MIN_SECRET_LENGTH` for why short values are ignored.
    """
    if value is None:
        return
    value = str(value)
    if len(value) < _MIN_SECRET_LENGTH:
        return
    with _secrets_lock:
        _secrets.add(value)


def redact(text):
    """Remove registered secrets and well-known credential formats from `text`."""
    with _secrets_lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, REDACTED)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFormatter(logging.Formatter):
    """A formatter that redacts the complete output, tracebacks included."""

    _colors = {
        logging.DEBUG: "\x1b[32m",
        logging.WARNING: "\x1b[33m",
        logging.ERROR: "\x1b[31m",
        logging.CRITICAL: "\x1b[1;31m",
    }

    def __init__(self, fmt=None, datefmt=None, color=False):
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._color = color

    def format(self, record):
        text = redact(super().format(record))
        color = self._colors.get(record.levelno) if self._color else None
        return f"{color}{text}\x1b[0m" if color else text


def _level_number(level):
    if level is None:
        return logging.INFO
    if isinstance(level, int):
        return level
    number = logging.getLevelName(str(level).upper())
    return number if isinstance(number, int) else logging.INFO


def get_logger(name=__name__, verbosity=None, debug_file=None, debug_filter=None):
    """
    Logging with secrets redacted from every handler

    :param name: logger name (use __name__ variable)
    :param verbosity:
    :return: Logger
    """
    global log_level
    if verbosity is not None:
        if log_level is None:
            log_level = verbosity
        else:
            raise RuntimeError("Verbosity has already been set.")

    global debug_logfile_handler
    if debug_file is not None:
        print(f"Setting up debug logfile {debug_file}")
        if debug_logfile_handler is None:
            debug_logfile_handler = logging.FileHandler(debug_file)
            debug_logfile_handler.setLevel(logging.DEBUG)
            debug_logfile_handler.setFormatter(
                RedactingFormatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
        else:
            raise RuntimeError("Debug logfile handler has already been initialized.")

    global debug_log_filter
    if debug_filter is not None:
        if debug_log_filter is None:
            debug_log_filter = debug_filter.split(",")
        else:
            raise RuntimeError("Debug log filter has already been set.")

    shortname = name.replace("pytr.", "")
    logger = logging.getLogger(shortname)
    logger.setLevel(logging.DEBUG)

    if debug_logfile_handler is not None and (debug_log_filter is None or shortname in debug_log_filter):
        if debug_logfile_handler not in logger.handlers:
            logger.addHandler(debug_logfile_handler)

    # no logging of libs
    logger.propagate = False

    if log_level == "debug":
        fmt = "%(asctime)s %(name)-9s %(levelname)-8s %(message)s"
        datefmt = "%Y-%m-%d %H:%M:%S%z"
    else:
        fmt = "%(asctime)s %(message)s"
        datefmt = "%H:%M:%S"

    # One console handler per logger, replaced on every call like coloredlogs did,
    # so the format and level follow the verbosity set last.
    for handler in list(logger.handlers):
        if getattr(handler, "_pytr_console", False):
            logger.removeHandler(handler)
    console = logging.StreamHandler(sys.stderr)
    console._pytr_console = True  # type: ignore[attr-defined]
    console.setLevel(_level_number(log_level))
    console.setFormatter(RedactingFormatter(fmt, datefmt, color=sys.stderr.isatty()))
    logger.addHandler(console)

    return logger


def preview(response, num_lines=5):
    lines = json.dumps(response, indent=2).splitlines()
    head = "\n".join(lines[:num_lines])
    tail = len(lines) - num_lines

    if tail <= 0:
        return f"{head}\n"
    else:
        return f"{head}\n{tail} more lines hidden"
