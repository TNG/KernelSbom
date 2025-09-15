from dataclasses import dataclass, field
import os
from pathlib import Path
import re
from typing import Iterator, Optional

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

def cmdfiles_in_dir(directory: str, 
                    exclude_dirs: list[str] = ['.git', 'Documentation', 'include', 'tools']) -> Iterator[str]:
    """Generate the iterator of .cmd files found under the directory.

    Walk under the given directory, and yield every .cmd file found.

    Args:
        directory: The directory to search for .cmd files.
        exclude_dirs: List of directories to skip when searching for .cmd files.

    Yields:
        The path to a .cmd file.
    """
    filename_matcher = re.compile(CMD_FILENAME_PATTERN)
    exclude_dirs = [ os.path.join(directory, d) for d in exclude_dirs ]

    for dirpath, dirnames, filenames in os.walk(directory, topdown=True):
        # Prune unwanted directories.
        if dirpath in exclude_dirs:
            dirnames[:] = []
            continue

        for filename in filenames:
            if filename_matcher.match(filename):
                cmd_file_path = os.path.join(dirpath, filename)
                yield cmd_file_path

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