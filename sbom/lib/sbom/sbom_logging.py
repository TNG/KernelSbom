# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import logging
import inspect
import sys
from typing import Any, Literal


class MessageLogger:
    """Logger that prints the first occurrence of each message immediately
    and keeps track of repeated messages for a final summary."""

    messages: dict[str, list[str]]

    def __init__(self, level: Literal["error", "warning"]) -> None:
        self._level = level
        self.messages = {}

    def log(self, template: str, /, **kwargs: Any) -> None:
        """Log a message based on a template and optional variables."""
        message = template.format(**kwargs)
        if template not in self.messages:
            self._emit(message)
            self.messages[template] = []
        self.messages[template].append(message)

    def flush_summary(self, summary_threshold: int = 3) -> None:
        """Print summary of collected messages."""
        for msgs in self.messages.values():
            for i, msg in enumerate(msgs):
                if i < summary_threshold:
                    self._emit(msg)
                    continue
                self._emit(
                    f"... (Found {len(msgs) - i} more {'instances' if (len(msgs) - i) != 1 else 'instance'} of this {self._level})"
                )
                break

    def _emit(self, message: str) -> None:
        """Emit the message at the appropriate logging level."""
        if self._level == "error":
            logging.error(message)
        elif self._level == "warning":
            logging.warning(message)


_warning_logger: MessageLogger
_error_logger: MessageLogger


def warning(msg_template: str, /, **kwargs: Any) -> None:
    """Log a warning message."""
    _warning_logger.log(msg_template, **kwargs)


def error(msg_template: str, /, **kwargs: Any) -> None:
    """Log an error message including file, line, and function context."""
    frame = inspect.currentframe()
    caller_frame = frame.f_back if frame else None
    info = inspect.getframeinfo(caller_frame) if caller_frame else None
    if info:
        msg_template = f'File "{info.filename}", line {info.lineno}, in {info.function}\n{msg_template}'
    _error_logger.log(msg_template, **kwargs)


def summarize_errors() -> None:
    """Flush a summary of collected errors. If errors were found exit 1"""
    if len(_error_logger.messages) == 0:
        return
    logging.error(
        f"Sbom generation failed with {len(_error_logger.messages)} "
        f"{'errors' if len(_error_logger.messages) != 1 else 'error'}:"
    )
    _error_logger.flush_summary()
    sys.exit(1)


def summarize_warnings() -> None:
    """Flush a summary of collected warnings."""
    if len(_warning_logger.messages) == 0:
        return
    logging.warning("Summarize warnings:")
    _warning_logger.flush_summary()


def init() -> None:
    global _warning_logger, _error_logger
    _warning_logger = MessageLogger("warning")
    _error_logger = MessageLogger("error")


init()
