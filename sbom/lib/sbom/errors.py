# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import logging
import inspect


_errors: list[str] = []


def log(msg: str) -> None:
    logging.error(msg)

    frame = inspect.currentframe()
    caller_frame = frame.f_back if frame else None
    info = inspect.getframeinfo(caller_frame) if caller_frame else None
    if info:
        msg = f'File "{info.filename}", line {info.lineno}, in {info.function}\n{msg}'
    _errors.append(msg)


def get() -> list[str]:
    return _errors


def clear() -> None:
    _errors.clear()
