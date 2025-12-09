# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
import re

from sbom.path_utils import PathStr

INCBIN_PATTERN = re.compile(r'\s*\.incbin\s+"(?P<path>[^"]+)"')
"""Regex pattern for matching `.incbin "<path>"` statements."""


@dataclass
class IncbinStatement:
    """A parsed `.incbin "<path>"` directive."""

    path: PathStr
    """path to the file referenced by the `.incbin` directive."""

    full_statement: str
    """Full `.incbin "<path>"` statement as it originally appeared in the file."""


def parse_incbin(absolute_path: PathStr) -> list[IncbinStatement]:
    """
    Parses `.incbin` directives from an `.S` assembly file.

    Args:
        absolute_path (PathStr): Absolute path to the `.S` assembly file.

    Returns:
        list[IncbinStatement]: Parsed `.incbin` statements.
    """
    with open(absolute_path, "rt") as f:
        content = f.read()
    return [
        IncbinStatement(
            path=match.group("path"),
            full_statement=match.group(0).strip(),
        )
        for match in INCBIN_PATTERN.finditer(content)
    ]
