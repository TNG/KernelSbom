#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only


from dataclasses import dataclass
from pathlib import Path
import re


MAKE_ERROR_PATTERNS = [
    r"No rule to make target '([^'\s]+)'",
    r"([^'\s]+): No such file or directory",
    r"cannot open ([^'\s]+): No such file",
]


@dataclass
class StraceOutputWithMakeError:
    lines: list[str]
    make_error_index: int
    make_error_missing_file_path: Path

    @property
    def make_error(self) -> str:
        return self.lines[self.make_error_index]

    @staticmethod
    def from_raw(strace_outputs_raw: list[str]) -> "StraceOutputWithMakeError":
        for i, line in enumerate(strace_outputs_raw):
            for pattern in MAKE_ERROR_PATTERNS:
                match = re.search(pattern, line)
                if match:
                    return StraceOutputWithMakeError(
                        strace_outputs_raw,
                        make_error_index=i,
                        make_error_missing_file_path=match.group(1),
                    )
        raise NotImplementedError("Build failed, but no make error could be detected.")
