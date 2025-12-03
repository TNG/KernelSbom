# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from itertools import chain
import logging
import os
from dataclasses import dataclass, field
import pickle
from typing import Iterator, Protocol

from sbom.cmd_graph.deps_parser import parse_cmd_file_deps
from sbom.cmd_graph.savedcmd_parser import parse_inputs_from_commands
from sbom.cmd_graph.incbin_parser import IncbinStatement, parse_incbin
from sbom.cmd_graph.cmd_file_parser import CmdFile, parse_cmd_file
import sbom.sbom_logging as sbom_logging
from sbom.path_utils import PathStr, is_relative_to
from .hardcoded_dependencies import get_hardcoded_dependencies


@dataclass
class IncbinDependency:
    node: "CmdGraphNode"
    full_statement: str


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


@dataclass
class CmdGraph:
    roots: list[CmdGraphNode] = field(default_factory=list[CmdGraphNode])


class CmdGraphConfig(Protocol):
    obj_tree: PathStr
    src_tree: PathStr
    fail_on_unknown_build_command: bool


def build_cmd_graph(root_paths: list[PathStr], config: CmdGraphConfig) -> CmdGraph:
    node_cache: dict[PathStr, CmdGraphNode] = {}
    root_nodes = [build_cmd_graph_node(root_path, config, node_cache) for root_path in root_paths]
    return CmdGraph(root_nodes)


def build_cmd_graph_node(
    target_path: PathStr,
    config: CmdGraphConfig,
    cache: dict[PathStr, CmdGraphNode] | None = None,
    depth: int = 0,
) -> CmdGraphNode:
    """
    Recursively builds a dependency graph starting from `target_path`.
    Dependencies are mainly discovered by parsing the `.<target_path.name>.cmd` file.

    Args:
        target_path (PathStr): Path to the target file relative to obj_tree.
        config (CmdGraphConfig): Config options
        cache (dict | None): Tracks processed nodes to prevent cycles.
        depth (int): Internal parameter to track the current recursion depth.
        log_depth (int): Maximum recursion depth up to which info-level messages are logged.

    Returns:
        CmdGraphNode: cmd graph node representing the target file
    """
    if cache is None:
        cache = {}

    target_file_absolute = (
        os.path.realpath(p) if os.path.islink(p := os.path.join(config.obj_tree, target_path)) else os.path.normpath(p)
    )

    if target_file_absolute in cache.keys():
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
    def _build_child_node(child_path: PathStr):
        return build_cmd_graph_node(child_path, config, cache, depth + 1)

    for hardcoded_dependency_path in get_hardcoded_dependencies(target_file_absolute, config.obj_tree, config.src_tree):
        node.hardcoded_dependencies.append(_build_child_node(hardcoded_dependency_path))

    if cmd_file is not None:
        for cmd_file_dependency_path in _parse_cmd_file_dependencies(
            cmd_file, target_path, config.obj_tree, config.src_tree, config.fail_on_unknown_build_command
        ):
            node.cmd_file_dependencies.append(_build_child_node(cmd_file_dependency_path))

    if node.absolute_path.endswith(".S"):
        for incbin_dependency_statement in _parse_incbin_statements(
            node.absolute_path, target_path, config.obj_tree, config.src_tree
        ):
            node.incbin_dependencies.append(
                IncbinDependency(
                    node=_build_child_node(incbin_dependency_statement.path),
                    full_statement=incbin_dependency_statement.full_statement,
                )
            )

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
    working_directory: PathStr | None = None
    for input_file in input_files:
        if os.path.isabs(input_file):
            cmd_file_dependencies.append(os.path.relpath(input_file, obj_tree))
            continue

        if working_directory is None:
            # Define working directory relative to obj_tree which is the directory from which the savedcommand was executed. All input_files should be relative to this working directory.
            # In the future there might be a way to parse the working directory directly from the cmd file. For now the working directory is estimated heuristically.
            working_directory = _get_working_directory(input_file, target_file, obj_tree, src_tree)
            if working_directory is None:
                sbom_logging.error(
                    "Skip children of node {target_path} because no working directory for relative input {input_file} could be found",
                    target_path=target_file,
                    input_file=input_file,
                )
                return []

        cmd_file_dependencies.append(os.path.normpath(os.path.join(working_directory, input_file)))

    # Remove target file from the dependency files to prevent cycles.
    # This is necessary because some multi stage commands first create an output and then pass it as input to the next command, e.g., objcopy.
    cmd_file_dependencies = [dependency for dependency in cmd_file_dependencies if dependency != target_file]
    return cmd_file_dependencies


def _parse_incbin_statements(
    assembly_path: PathStr, target_path: PathStr, obj_tree: PathStr, src_tree: PathStr
) -> list[IncbinStatement]:
    incbin_statements = parse_incbin(assembly_path)
    if len(incbin_statements) == 0:
        return []
    working_directory = _get_working_directory(incbin_statements[0].path, target_path, obj_tree, src_tree)
    if working_directory is None:
        sbom_logging.error(
            f"Skip children of node {target_path} because no working directory for {incbin_statements[0]} could be found"
        )
        return []
    return [
        IncbinStatement(
            path=os.path.normpath(os.path.join(working_directory, incbin_statement.path)),
            full_statement=incbin_statement.full_statement,
        )
        for incbin_statement in incbin_statements
    ]


def iter_cmd_graph(cmd_graph: CmdGraph | CmdGraphNode) -> Iterator[CmdGraphNode]:
    visited: set[PathStr] = set()
    node_stack: list[CmdGraphNode] = cmd_graph.roots.copy() if isinstance(cmd_graph, CmdGraph) else [cmd_graph]
    while len(node_stack) > 0:
        node = node_stack.pop(0)
        if node.absolute_path in visited:
            continue

        visited.add(node.absolute_path)
        node_stack = list(chain(node.children, node_stack))
        yield node


def save_cmd_graph(node: CmdGraph, path: PathStr) -> None:
    with open(path, "wb") as f:
        pickle.dump(node, f)


def load_cmd_graph(path: PathStr) -> CmdGraph:
    with open(path, "rb") as f:
        return pickle.load(f)


def build_or_load_cmd_graph(target_paths: list[PathStr], cmd_graph_path: PathStr, config: CmdGraphConfig) -> CmdGraph:
    if os.path.exists(cmd_graph_path):
        logging.debug("Load cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
    else:
        logging.debug("Build cmd graph")
        cmd_graph = build_cmd_graph(target_paths, config)
        save_cmd_graph(cmd_graph, cmd_graph_path)
    return cmd_graph


def _to_cmd_path(path: PathStr) -> PathStr:
    name = os.path.basename(path)
    return path.removesuffix(name) + f".{name}.cmd"


def _get_working_directory(
    input_file: PathStr, target_path: PathStr, obj_tree: PathStr, src_tree: PathStr
) -> PathStr | None:
    """
    Input paths in .cmd files are often relative paths but it is unclear to which original working directory these paths are relative to.
    This function heuristically estimates the working directory for a given input_file and returns the working directory relative to the output tree.
    """

    relative_to_cmd_file = os.path.exists(os.path.join(obj_tree, os.path.dirname(target_path), input_file))
    relative_to_obj_tree = os.path.exists(os.path.join(obj_tree, input_file))
    relative_to_tools_objtool = target_path.startswith("tools/objtool/arch/x86")
    relative_to_tools_lib_subcmd = target_path.startswith("tools/objtool/libsubcmd")

    if relative_to_cmd_file:
        return os.path.dirname(target_path)
    elif relative_to_obj_tree:
        return "."
    elif relative_to_tools_objtool:
        # Input path relative to `tools/objtool` (e.g., `tools/objtool/arch/x86/special.o` has input `arch/x86/special.c`)
        return os.path.join(os.path.relpath(src_tree, obj_tree), "tools/objtool")
    elif relative_to_tools_lib_subcmd:
        # Input path relative to `tools/lib/subcmd` (e.g., `tools/objtool/libsubcmd/.sigchain.o` has input `subcmd-util.h` which lives in `tools/lib/subcmd/subcmd-util.h`)
        return os.path.join(os.path.relpath(src_tree, obj_tree), "tools/lib/subcmd")

    return None


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
