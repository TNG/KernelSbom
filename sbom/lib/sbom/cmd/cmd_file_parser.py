# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

SAVEDCMD_PATTERN = r"^savedcmd_.*?:=\s*(?P<full_command>.+)$"
SOURCE_PATTERN = r"^source.*?:=\s*(?P<full_command>.+)$"


@dataclass
class CmdFile:
    cmd_file_path: Path
    savedcmd: str
    source: Optional[str] = None
    deps: list[str] = field(default_factory=list[str])
    make_rules: list[str] = field(default_factory=list[str])


def parse_cmd_file(cmd_file_path: Path) -> CmdFile:
    """
    Parses a .cmd file.

    Args:
        cmd_file_path (Path): absolute Path to a .cmd file

    Returns:
        cmd_file (CmdFile): Parsed cmd file.
    """
    with open(cmd_file_path, "rt") as f:
        lines = [line.strip() for line in f.readlines() if line.strip() != ""]

    # savedcmd
    line0 = re.compile(SAVEDCMD_PATTERN).match(lines[0])
    if line0 is None:
        raise ValueError(f"No 'savedcmd_' command found in {cmd_file_path}")
    savedcmd = line0.group("full_command")

    if len(lines) == 1:
        return CmdFile(cmd_file_path, savedcmd)

    # source
    line1 = re.compile(SOURCE_PATTERN).match(lines[1])
    if line1 is None:
        raise ValueError(f"No 'source_' command found in second line of {cmd_file_path}")
    source = line1.group("full_command")

    # deps
    deps: list[str] = []
    i = 3  # lines[2] includes the variable assignment but no actual dependency, so we need to start at lines[3].
    while True:
        if not lines[i].endswith("\\"):
            break
        deps.append(lines[i][:-1].strip())
        i += 1

    # make_rules
    make_rules = lines[i:]

    return CmdFile(cmd_file_path, savedcmd, source, deps, make_rules)
