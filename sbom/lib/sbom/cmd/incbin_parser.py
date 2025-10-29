# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from pathlib import Path
import re

INCBIN_PATTERN = re.compile(r'\s*\.incbin\s+"(?P<filename>[^"]+)"')
"""Regex that matches: .incbin "file" statements"""


def parse_incbin(path: Path) -> list[Path]:
    """
    File dependencies via .incbin statements in .S assembly files are not covered by the .cmd file dependency mechanism.

    Args:
        path (Path): absolute path to a .S assembly file

    Returns:
        dependencies (list[Path]): list of paths included via .incbin statements
    """
    with open(path, "rt") as f:
        content = f.read()
    return [Path(match.group("filename")) for match in INCBIN_PATTERN.finditer(content)]
