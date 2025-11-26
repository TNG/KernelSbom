# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
import re

from sbom.path_utils import PathStr

INCBIN_PATTERN = re.compile(r'\s*\.incbin\s+"(?P<filename>[^"]+)"')
"""Regex that matches: .incbin "file" statements"""


@dataclass
class IncbinStatement:
    path: PathStr
    full_statement: str


def parse_incbin(path: PathStr) -> list[IncbinStatement]:
    """
    File dependencies via .incbin statements in .S assembly files are not covered by the .cmd file dependency mechanism.

    Args:
        path (PathStr): absolute path to a .S assembly file

    Returns:
        dependencies (list[PathStr, str]): list of paths included via .incbin statements
    """
    with open(path, "rt") as f:
        content = f.read()
    return [
        IncbinStatement(
            path=match.group("filename"),
            full_statement=match.group(0).strip(),
        )
        for match in INCBIN_PATTERN.finditer(content)
    ]
