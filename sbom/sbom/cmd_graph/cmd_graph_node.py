# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass, field
from itertools import chain
import logging
import os
from typing import Iterator, Protocol

from sbom import sbom_logging
from sbom.cmd_graph.cmd_file_parser import CmdFile, parse_cmd_file
from sbom.cmd_graph.deps_parser import parse_cmd_file_deps
from sbom.cmd_graph.hardcoded_dependencies import get_hardcoded_dependencies
from sbom.cmd_graph.incbin_parser import parse_incbin
from sbom.cmd_graph.savedcmd_parser import parse_inputs_from_commands
from sbom.path_utils import PathStr, is_relative_to


@dataclass
class IncbinDependency:
    node: "CmdGraphNode"
    full_statement: str


class CmdGraphNodeConfig(Protocol):
    obj_tree: PathStr
    src_tree: PathStr
    fail_on_unknown_build_command: bool


@dataclass
class CmdGraphNode:
    """A node in the cmd graph representing a single file and its dependencies."""

    absolute_path: PathStr
    """Absolute path to the file this node represents."""

    cmd_file: CmdFile | None = None
    """Parsed .cmd file describing how the file at absolute_path was built, or None if not available."""

    cmd_file_dependencies: list["CmdGraphNode"] = field(default_factory=list["CmdGraphNode"])
    incbin_dependencies: list[IncbinDependency] = field(default_factory=list[IncbinDependency])
    hardcoded_dependencies: list["CmdGraphNode"] = field(default_factory=list["CmdGraphNode"])

    @property
    def children(self) -> Iterator["CmdGraphNode"]:
        seen: set[PathStr] = set()
        for node in chain(
            self.cmd_file_dependencies,
            (dep.node for dep in self.incbin_dependencies),
            self.hardcoded_dependencies,
        ):
            if node.absolute_path not in seen:
                seen.add(node.absolute_path)
                yield node

    @classmethod
    def create(
        cls,
        target_path: PathStr,
        config: CmdGraphNodeConfig,
        cache: dict[PathStr, "CmdGraphNode"] | None = None,
        depth: int = 0,
    ) -> "CmdGraphNode":
        """
        Recursively builds a dependency graph starting from `target_path`.
        Dependencies are mainly discovered by parsing the `.<target_path.name>.cmd` file.

        Args:
            target_path (PathStr): Path to the target file relative to obj_tree.
            config (CmdGraphNodeConfig): Config options
            cache (dict | None): Tracks processed nodes to prevent cycles.
            depth (int): Internal parameter to track the current recursion depth.
            log_depth (int): Maximum recursion depth up to which info-level messages are logged.

        Returns:
            CmdGraphNode: cmd graph node representing the target file
        """
        if cache is None:
            cache = {}

        target_file_absolute = (
            os.path.realpath(p)
            if os.path.islink(p := os.path.join(config.obj_tree, target_path))
            else os.path.normpath(p)
        )

        if target_file_absolute in cache:
            return cache[target_file_absolute]

        if depth == 0:
            logging.debug(f"Build node: {'  ' * depth}{target_path}")
        cmd_path = _to_cmd_path(target_file_absolute)
        cmd_file = parse_cmd_file(cmd_path) if os.path.exists(cmd_path) else None
        node = CmdGraphNode(target_file_absolute, cmd_file)
        cache[target_file_absolute] = node

        if not os.path.exists(target_file_absolute):
            if is_relative_to(target_file_absolute, config.obj_tree) or is_relative_to(
                target_file_absolute, config.src_tree
            ):
                sbom_logging.error(
                    "Skip parsing '{target_path_absolute}' because file does not exist",
                    target_path_absolute=target_file_absolute,
                )
            else:
                sbom_logging.warning(
                    "Skip parsing {target_path_absolute} because file does not exist",
                    target_path_absolute=target_file_absolute,
                )
            return node

        # Search for dependencies to add to the graph as child nodes. Child paths are always relative to the output tree.
        def _build_child_node(child_path: PathStr) -> "CmdGraphNode":
            return CmdGraphNode.create(child_path, config, cache, depth + 1)

        for hardcoded_dependency_path in get_hardcoded_dependencies(
            target_file_absolute, config.obj_tree, config.src_tree
        ):
            node.hardcoded_dependencies.append(_build_child_node(hardcoded_dependency_path))

        if cmd_file is not None:
            for cmd_file_dependency_path in _parse_cmd_file_dependencies(
                cmd_file, target_path, config.obj_tree, config.src_tree, config.fail_on_unknown_build_command
            ):
                node.cmd_file_dependencies.append(_build_child_node(cmd_file_dependency_path))

        if node.absolute_path.endswith(".S"):
            node.incbin_dependencies = [
                IncbinDependency(
                    node=_build_child_node(incbin_statement.path),
                    full_statement=incbin_statement.full_statement,
                )
                for incbin_statement in parse_incbin(node.absolute_path)
            ]

        return node


def _parse_cmd_file_dependencies(
    cmd_file: CmdFile, target_file: PathStr, obj_tree: PathStr, src_tree: PathStr, fail_on_unknown_build_command: bool
) -> list[PathStr]:
    """
    Parses the cmd file of a given target file and returns a list of all dependency files required to build the target file.

    Args:
        cmd_file (CmdFile): The command file describing how the target file was built
        target_file (PathStr): File being built.

    Returns:
        list[PathStr]: Resolved dependency file paths relative to `obj_tree`.
    """
    input_files: list[PathStr] = [
        str(p) for p in parse_inputs_from_commands(cmd_file.savedcmd, fail_on_unknown_build_command)
    ]
    if cmd_file.deps:
        input_files += [str(p) for p in parse_cmd_file_deps(cmd_file.deps)]
    input_files = _expand_resolve_files(input_files, obj_tree)

    cmd_file_dependencies: list[PathStr] = []
    for input_file in input_files:
        # input files are either absolute or relative to the object tree
        if os.path.isabs(input_file):
            input_file = os.path.relpath(input_file, obj_tree)
        if input_file == target_file:
            # Skip target file to prevent cycles. This is necessary because some multi stage commands first create an output and then pass it as input to the next command, e.g., objcopy.
            continue
        cmd_file_dependencies.append(input_file)

    return cmd_file_dependencies


def _to_cmd_path(path: PathStr) -> PathStr:
    name = os.path.basename(path)
    return path.removesuffix(name) + f".{name}.cmd"


def _expand_resolve_files(input_files: list[PathStr], obj_tree: PathStr) -> list[PathStr]:
    expanded_input_files: list[PathStr] = []
    for input_file in input_files:
        input_file_str = str(input_file)
        if not input_file_str.startswith("@"):
            expanded_input_files.append(input_file)
            continue
        with open(os.path.join(obj_tree, input_file_str[1:]), "r") as f:
            resolve_file_content = [line.strip() for line in f.readlines() if line.strip()]
        expanded_input_files += _expand_resolve_files(resolve_file_content, obj_tree)
    return expanded_input_files
