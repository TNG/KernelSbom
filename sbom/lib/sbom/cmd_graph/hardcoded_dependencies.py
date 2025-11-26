# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import os
from typing import Callable
import sbom.errors as sbom_errors
from sbom.path_utils import PathStr, is_relative_to
from sbom.environment import Environment

HARDCODED_DEPENDENCIES: dict[str, list[str]] = {
    # defined in linux/Kbuild
    "include/generated/rq-offsets.h": ["kernel/sched/rq-offsets.s"],
    "kernel/sched/rq-offsets.s": ["include/generated/asm-offsets.h"],
    "include/generated/bounds.h": ["kernel/bounds.s"],
    "include/generated/asm-offsets.h": ["arch/{arch}/kernel/asm-offsets.s"],
}


def get_hardcoded_dependencies(path: PathStr, output_tree: PathStr, src_tree: PathStr) -> list[PathStr]:
    """
    Some files in the Linux kernel build process are not tracked by the .cmd dependency mechanism.
    This function provides a temporary workaround by manually specifying known missing dependencies required to correctly model the build graph.

    Args:
        path (Path): absolute path to a file within the src tree or output tree.
        output_tree (Path): absolute Path to the base directory of the output tree.
        src_tree (Path): absolute Path to the `linux` source directory.

    Returns:
        list[Path]: A list of dependency file paths (relative to the output tree) required to build the file at the given path.
    """
    key: str | None = None
    if is_relative_to(path, output_tree):
        key = os.path.relpath(path, output_tree)
    elif is_relative_to(path, src_tree):
        key = os.path.relpath(path, src_tree)

    if key is None or key not in HARDCODED_DEPENDENCIES:
        return []

    template_variables: dict[str, Callable[[], str | None]] = {
        "arch": lambda: _get_arch(path),
    }

    dependencies: list[PathStr] = []
    for template in HARDCODED_DEPENDENCIES[key]:
        dependency = _evaluate_template(template, template_variables)
        if dependency is None:
            continue
        if os.path.exists(os.path.join(output_tree, dependency)):
            dependencies.append(dependency)
        elif os.path.exists(os.path.join(src_tree, dependency)):
            dependencies.append(os.path.relpath(dependency, output_tree))
        else:
            sbom_errors.log(
                f"Skip hardcoded dependency '{dependency}' for '{path}' because the dependency lies neither in the src tree nor the output tree."
            )

    return dependencies


def _evaluate_template(template: str, variables: dict[str, Callable[[], str | None]]) -> str | None:
    for key, value_function in variables.items():
        templateKey = "{" + key + "}"
        if templateKey in template:
            value = value_function()
            if value is None:
                return None
            template = template.replace(templateKey, value)
    return template


def _get_arch(path: PathStr):
    srcarch = Environment.SRCARCH
    if srcarch is None:
        sbom_errors.log(
            f"Skip architecture specific hardcoded dependency for '{path}' because the SRCARCH environment variable was not set."
        )
        return None
    return srcarch
