# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import os
import re
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field

CMD_FILENAME_PATTERN = r"^\..*\.cmd$"
COMMAND_PATTERN = r"^savedcmd_.*?:=\s*(?P<full_command>.+)$"
SOURCE_PATTERN = r"^source.*?:=\s*(?P<full_command>.+)$"


@dataclass
class CmdFile:
    cmd_file_path: Path
    savedcmd: str
    source: Optional[str] = None
    deps: list[str] = field(default_factory=list)
    make_rules: list[str] = field(default_factory=list)


def parse_cmd_file(cmd_file_path: Path) -> CmdFile:
    """
    Parses a .cmd file.

    Args:
        cmd_file_path (Path): Path to the .cmd file, relative or absolute.

    Returns:
        cmd_file (CmdFile): Parsed cmd file.
    """
    with open(cmd_file_path, "rt") as f:
        lines = [line.strip() for line in f.readlines() if line.strip() != ""]

    # cmd_file_path
    cmd_file_path = Path(os.path.realpath(cmd_file_path))

    # savedcmd
    line0 = re.compile(COMMAND_PATTERN).match(lines[0])
    savedcmd = line0.group("full_command")

    if len(lines) == 1:
        return CmdFile(cmd_file_path, savedcmd)

    # source
    line1 = re.compile(SOURCE_PATTERN).match(lines[1])
    source = os.path.realpath(os.path.join(cmd_file_path.parent, line1.group("full_command")))

    # deps
    deps = []
    i = 3  # lines[2] includes the variable assignment but no actual dependency, so we need to start at lines[3].
    while True:
        if not lines[i].endswith("\\"):
            break
        deps.append(lines[i][:-1].strip())
        i += 1

    # make_rules
    make_rules = lines[i:]

    return CmdFile(cmd_file_path, savedcmd, source, deps, make_rules)
