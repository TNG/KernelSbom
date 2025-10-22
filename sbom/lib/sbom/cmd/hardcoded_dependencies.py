# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from pathlib import Path
import os
from typing import Callable
import logging

HARDCODED_DEPENDENCIES: dict[str, list[str]] = {
    # defined in linux/Kbuild
    "include/generated/rq-offsets.h": ["kernel/sched/rq-offsets.s"],
    "kernel/sched/rq-offsets.s": ["include/generated/asm-offsets.h"],
    "include/generated/bounds.h": ["kernel/bounds.s"],
}

ARCHITECTURE_SPECIFIC_HARDCODED_DEPENDENCIES: dict[str, Callable[[str], list[str]]] = {
    # defined in linux/Kbuild
    "include/generated/asm-offsets.h": (lambda arch: [f"arch/{arch}/kernel/asm-offsets.s"]),
}


def get_hardcoded_dependencies(path: Path) -> list[Path]:
    """
    Some files in the Linux kernel build process are not tracked by the .cmd dependency mechanism.
    This function provides a temporary workaround by manually specifying known missing dependencies required to correctly model the build graph.

    Args:
        path (Path): Path to a file relative to the kernel build output tree.

    Returns:
        list[Path]: A list of dependency file paths (relative to the output tree) required to build the file at the given path.
    """
    if str(path) in HARDCODED_DEPENDENCIES.keys():
        return [Path(p) for p in HARDCODED_DEPENDENCIES[str(path)]]

    if str(path) in ARCHITECTURE_SPECIFIC_HARDCODED_DEPENDENCIES.keys():
        srcarch = os.environ.get("SRCARCH")
        if srcarch is None:
            logging.warning(
                f"Skip architecture specific hardcoded dependency for '{path}' because the SRCARCH environment variable was not set."
            )
            return []
        return [Path(p) for p in ARCHITECTURE_SPECIFIC_HARDCODED_DEPENDENCIES[str(path)](srcarch)]

    return []
