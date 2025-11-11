# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import re
from dataclasses import dataclass, field
import sbom.errors as sbom_errors
from sbom.path_utils import PathStr

SAVEDCMD_PATTERN = re.compile(r"^(saved)?cmd_.*?:=\s*(?P<full_command>.+)$")
SOURCE_PATTERN = re.compile(r"^source.*?:=\s*(?P<source_file>.+)$")


@dataclass
class CmdFile:
    cmd_file_path: PathStr
    savedcmd: str
    source: PathStr | None = None
    deps: list[str] = field(default_factory=list[str])
    make_rules: list[str] = field(default_factory=list[str])


def parse_cmd_file(cmd_file_path: PathStr) -> CmdFile | None:
    """
    Parses a .cmd file.
    .cmd files can have the following structures:
    1. Full Cmd File
        (saved)?cmd_<output> := <command>
        source_<output> := <main_input>
        deps_<output> := \
          <dependencies>
        <output> := $(deps_<output>)
        $(deps_<output>):

    2. Command Only Cmd File
        (saved)?cmd_<output> := <command>
        
    3. Single Dependency Cmd File
        (saved)?cmd_<output> := <command>
        <output> := <dependency>


    Args:
        cmd_file_path (Path): absolute Path to a .cmd file

    Returns:
        cmd_file (CmdFile): Parsed cmd file.
    """
    with open(cmd_file_path, "rt") as f:
        lines = [line.strip() for line in f.readlines() if line.strip() != ""]

    # savedcmd
    match = SAVEDCMD_PATTERN.match(lines[0])
    if match is None:
        sbom_errors.log(f"Skip parsing '{cmd_file_path}' because no 'savedcmd_' command was found.")
        return None
    savedcmd = match.group("full_command")

    # Command Only Cmd File
    if len(lines) == 1:
        return CmdFile(cmd_file_path, savedcmd)

    # Single Dependency Cmd File
    if len(lines) == 2:
        dep = lines[1].split(":")[1].strip()
        return CmdFile(cmd_file_path, savedcmd, deps=[dep])

    # Full Cmd File
    # source
    line1 = SOURCE_PATTERN.match(lines[1])
    if line1 is None:
        sbom_errors.log(f"Skip parsing '{cmd_file_path}' because no 'source_' entry was found.")
        return CmdFile(cmd_file_path, savedcmd)
    source = line1.group("source_file")

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
