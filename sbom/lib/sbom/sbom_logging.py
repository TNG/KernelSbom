# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import logging
import inspect
from typing import Any, Literal


class MessageLogger:
    """Logger that prints the first occurrence of each message immediately
    and keeps track of repeated messages for a final summary."""

    messages: dict[str, list[str]]
    repeated_logs_limit: int
    """Maximum number of repeated messages of the same type to log before suppressing further output."""

    def __init__(self, level: Literal["error", "warning"], repeated_logs_limit: int = 3) -> None:
        self._level = level
        self.messages = {}
        self.repeated_logs_limit = repeated_logs_limit

    def log(self, template: str, /, **kwargs: Any) -> None:
        """Log a message based on a template and optional variables."""
        message = template.format(**kwargs)
        if template not in self.messages:
            self.messages[template] = []
        if len(self.messages[template]) < self.repeated_logs_limit:
            if self._level == "error":
                logging.error(message)
            elif self._level == "warning":
                logging.warning(message)
        self.messages[template].append(message)

    def get_summary(self) -> str:
        """Return summary of collected messages."""
        if len(self.messages) == 0:
            return ""
        summary: list[str] = [f"Summarize {self._level}s:"]
        for msgs in self.messages.values():
            for i, msg in enumerate(msgs):
                if i < self.repeated_logs_limit:
                    summary.append(msg)
                    continue
                summary.append(
                    f"... (Found {len(msgs) - i} more {'instances' if (len(msgs) - i) != 1 else 'instance'} of this {self._level})"
                )
                break
        return "\n".join(summary)


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


def summarize_warnings() -> str:
    return _warning_logger.get_summary()


def summarize_errors() -> str:
    return _error_logger.get_summary()


def has_errors() -> bool:
    return len(_error_logger.messages) > 0


def init() -> None:
    global _warning_logger, _error_logger
    _warning_logger = MessageLogger("warning")
    _error_logger = MessageLogger("error")


init()
