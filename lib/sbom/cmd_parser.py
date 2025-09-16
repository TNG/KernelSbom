#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2025: Luis Augenstein <luis.augenstein@tngtech.com>.

from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Optional

CMD_FILENAME_PATTERN = r'^\..*\.cmd$'
COMMAND_PATTERN = r'^savedcmd_.*?:=\s*(?P<full_command>.+)$'
SOURCE_PATTERN = r'^source.*?:=\s*(?P<full_command>.+)$'

@dataclass
class CmdFile():
    cmd_file_path: str
    savedcmd: str
    source: Optional[str] = None
    deps: list[str] = field(default_factory=list)
    make_rules: list[str] = field(default_factory=list)

def parse_cmd_file(cmd_file_path: str) -> CmdFile:
    with open(cmd_file_path, 'rt') as f:
        lines = [line.strip() for line in f.readlines() if line.strip() != ""]
    
    # cmd_file_path
    cmd_file_path = os.path.realpath(cmd_file_path)

    # savedcmd
    line1 = re.compile(COMMAND_PATTERN).match(lines[0])

    savedcmd = line1.group('full_command')

    if len(lines) == 1:
        return CmdFile(cmd_file_path, savedcmd)

    # source
    line2 = re.compile(SOURCE_PATTERN).match(lines[1])
    source = os.path.realpath(os.path.join(Path(cmd_file_path).parent, line2.group('full_command')))

    # deps
    deps = []
    i = 3
    while True:
        if not lines[i].endswith('\\'):
            break
        deps.append(lines[i][:-1].strip())
        i += 1
    
    # make_rules
    make_rules = lines[i:]
       
    return CmdFile(cmd_file_path, savedcmd, source, deps, make_rules)