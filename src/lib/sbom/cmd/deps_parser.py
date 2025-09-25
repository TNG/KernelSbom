# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import re


WILDCARD_PATTERN = re.compile(r"\$\(wildcard ([^)]+)\)")
SOURCE_FILE_PATTERN = re.compile(r".*\.(h|c|S)$")


def parse_deps(deps: list[str], output_tree: Path) -> list[Path]:
    """
    Parse dependency strings of a .cmd file and return valid input file paths.

    Supports:
    - $(wildcard ...) paths relative to output_tree (only returned if the file exists)
    - Source files ending in .h, .c, or .S (returned as-is)

    Args:
        deps: List of dependency strings as found in `.cmd` files.
        output_tree: Base directory for resolving wildcard paths.

    Returns:
        input_files: List of input file paths
    """
    input_files: list[Path] = []
    for dep in deps:
        dep = dep.strip()
        match dep:
            case _ if wildcard_match := WILDCARD_PATTERN.match(dep):
                config_path_in_tree = wildcard_match.group(1)
                # expect config path to be "$(wildcard include/config/<CONFIG_NAME>)"
                if Path(output_tree / config_path_in_tree).exists():
                    input_files.append(Path(config_path_in_tree))

            case _ if SOURCE_FILE_PATTERN.match(dep):
                input_files.append(Path(dep))

            case _:
                raise NotImplementedError(f"Unrecognized dependency format: {dep}")
    return input_files
