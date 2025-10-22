# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from pathlib import Path
import re
import sbom.errors as sbom_errors

CONFIG_PATTERN = re.compile(r"\$\(wildcard (include/config/[^)]+)\)")
VALID_PATH_PATTERN = re.compile(r"^(\/)?(([\w\-\., ]*)\/)*[\w\-\., ]+$")


def parse_deps(deps: list[str]) -> list[Path]:
    """
    Parse dependency strings of a .cmd file and return valid input file paths.
    Args:
        deps: List of dependency strings as found in `.cmd` files.
    Returns:
        input_files: List of input file paths
    """
    input_files: list[Path] = []
    for dep in deps:
        dep = dep.strip()
        match dep:
            case _ if _ := CONFIG_PATTERN.match(dep):
                # config paths like include/config/<CONFIG_NAME> are not included in the graph
                continue
            case _ if VALID_PATH_PATTERN.match(dep):
                input_files.append(Path(dep))

            case _:
                sbom_errors.log(f"Skip parsing dependency {dep} because of unrecognized format")
    return input_files
