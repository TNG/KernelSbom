import os
import re
from typing import Iterator

CMD_FILENAME_PATTERN = r'^\..*\.cmd$'

class CmdFile():
    ...

def cmdfiles_in_dir(directory: str, 
                    exclude_dirs: list[str] = ['.git', 'Documentation', 'include', 'tools']) -> Iterator[CmdFile]:
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
                yield parse_cmd_file(cmd_file_path)

def parse_cmd_file(cmd_file_path: str) -> CmdFile:
    return CmdFile()