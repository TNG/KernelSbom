# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

import os

PathStr = str
"""Filesystem path represented as a plain string for better performance than pathlib.Path."""


def is_relative_to(path: PathStr, base: PathStr) -> bool:
    return os.path.commonpath([path, base]) == base
