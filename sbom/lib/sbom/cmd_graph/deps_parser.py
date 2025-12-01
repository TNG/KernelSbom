# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import re
import sbom.sbom_logging as sbom_logging
from sbom.path_utils import PathStr

CONFIG_PATTERN = re.compile(r"\$\(wildcard (include/config/[^)]+)\)")
OBJTOOL_PATTERN = re.compile(r"\$\(wildcard \./tools/objtool/objtool\)")
WILDCARD_PATTERN = re.compile(r"\$\(wildcard (?P<path>[^)]+)\)")
VALID_PATH_PATTERN = re.compile(r"^(\/)?(([\w\-\., ]*)\/)*[\w\-\., ]+$")


def parse_deps(deps: list[str]) -> list[PathStr]:
    """
    Parse dependency strings of a .cmd file and return valid input file paths.
    Args:
        deps: List of dependency strings as found in `.cmd` files.
    Returns:
        input_files: List of input file paths
    """
    input_files: list[PathStr] = []
    for dep in deps:
        dep = dep.strip()
        match dep:
            case _ if _ := CONFIG_PATTERN.match(dep) or OBJTOOL_PATTERN.match(dep):
                # config paths like include/config/<CONFIG_NAME> are not included in the graph
                continue
            case _ if match := WILDCARD_PATTERN.match(dep):
                path = match.group("path")
                input_files.append(path)
            case _ if VALID_PATH_PATTERN.match(dep):
                input_files.append(dep)

            case _:
                sbom_logging.error("Skip parsing dependency {dep} because of unrecognized format", dep=dep)
    return input_files
