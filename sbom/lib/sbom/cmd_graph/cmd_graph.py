# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


import logging
import os
from dataclasses import dataclass, field
import pickle
from typing import Iterator

from sbom.cmd_graph.deps_parser import parse_deps
from sbom.cmd_graph.savedcmd_parser import parse_commands
from sbom.cmd_graph.incbin_parser import parse_incbin
from sbom.cmd_graph.cmd_file_parser import CmdFile, parse_cmd_file
import sbom.errors as sbom_errors
from sbom.path_utils import PathStr, is_relative_to
from .hardcoded_dependencies import get_hardcoded_dependencies


@dataclass
class CmdGraphNode:
    absolute_path: PathStr
    cmd_file: CmdFile | None = None
    children: list["CmdGraphNode"] = field(default_factory=list["CmdGraphNode"])


@dataclass
class CmdGraph:
    roots: list[CmdGraphNode] = field(default_factory=list[CmdGraphNode])


def build_cmd_graph(root_paths: list[PathStr], output_tree: PathStr, src_tree: PathStr, log_depth: int = 0) -> CmdGraph:
    node_cache: dict[PathStr, CmdGraphNode] = {}
    root_nodes = [
        build_cmd_graph_node(str(root_path), str(output_tree), str(src_tree), node_cache, log_depth=log_depth)
        for root_path in root_paths
    ]
    return CmdGraph(root_nodes)


def build_cmd_graph_node(
    root_path: PathStr,
    output_tree: PathStr,
    src_tree: PathStr,
    cache: dict[PathStr, CmdGraphNode] | None = None,
    depth: int = 0,
    log_depth: int = 0,
) -> CmdGraphNode:
    """
    Recursively builds a dependency graph starting from `root_path`.
    Dependencies are mainly discovered by parsing the `.<root_path.name>.cmd` file.

    Args:
        root_path (Path): Path to the root output file relative to output_tree.
        output_tree (Path): absolute Path to the base directory of the output_tree.
        src_tree (Path): absolute Path to the `linux` source directory.
        cache (dict | None): Tracks processed nodes to prevent cycles.
        depth (int): Internal parameter to track the current recursion depth.
        log_depth (int): Maximum recursion depth up to which info-level messages are logged.

    Returns:
        CmdGraphNode: Root of the command dependency graph.
    """
    if cache is None:
        cache = {}

    root_path_absolute = os.path.normpath(os.path.join(output_tree, root_path))
    if root_path_absolute in cache.keys():
        if depth <= log_depth:
            logging.info(f"Reuse Node: {'  ' * depth}{root_path}")
        return cache[root_path_absolute]

    if depth <= log_depth:
        logging.info(f"Build Node: {'  ' * depth}{root_path}")
    cmd_path = _to_cmd_path(root_path_absolute)
    cmd_file = parse_cmd_file(cmd_path) if os.path.exists(cmd_path) else None
    node = CmdGraphNode(root_path_absolute, cmd_file)
    cache[root_path_absolute] = node

    if not os.path.exists(root_path_absolute):
        if is_relative_to(root_path_absolute, output_tree) or is_relative_to(root_path_absolute, src_tree):
            sbom_errors.log(f"Skip parsing '{root_path_absolute}' because file does not exist")
        else:
            logging.warning(f"Skip parsing {root_path_absolute} because file does not exist")
        return node

    # Search for dependencies to add to the graph as child nodes. Child paths are always relative to the output tree.
    child_paths = get_hardcoded_dependencies(root_path_absolute, output_tree, src_tree)
    if cmd_file is not None:
        child_paths += _parse_cmd_file(cmd_file, output_tree, src_tree, root_path)
    if node.absolute_path.endswith(".S"):
        child_paths += _parse_incbin(node.absolute_path, output_tree, src_tree, root_path)

    # Create child nodes
    for child_path in child_paths:
        child_node = build_cmd_graph_node(child_path, output_tree, src_tree, cache, depth + 1, log_depth)
        node.children.append(child_node)

    return node


def _parse_cmd_file(
    cmd_file: CmdFile, output_tree: PathStr, src_tree: PathStr, root_artifact: PathStr
) -> list[PathStr]:
    input_files: list[PathStr] = [str(p) for p in parse_commands(cmd_file.savedcmd)]
    if cmd_file.deps:
        input_files += [str(p) for p in parse_deps(cmd_file.deps)]
    input_files = _expand_resolve_files(input_files, output_tree)

    child_paths: list[PathStr] = []
    working_directory: PathStr | None = None
    for input_file in input_files:
        if os.path.isabs(input_file):
            child_paths.append(os.path.relpath(input_file, output_tree))
            continue

        if working_directory is None:
            # Define working directory relative to output_tree which is the directory from which the savedcommand was executed. All input_files should be relative to this working directory.
            # In the future there might be a way to parse this directly from the cmd file. For now the working directory is estimated heuristically.
            working_directory = _get_working_directory(input_file, output_tree, src_tree, root_artifact)
            if working_directory is None:
                sbom_errors.log(
                    f"Skip children of node {root_artifact} because no working directory for relative input {input_file} could be found"
                )
                return []

        child_paths.append(os.path.normpath(os.path.join(working_directory, input_file)))

    # Remove root output from the input_files to prevent cycles.
    # Some multi stage commands create an output and pass it as input to the next command, e.g., objcopy.
    child_paths = [child_path for child_path in child_paths if child_path != root_artifact]
    return child_paths


def _parse_incbin(
    assembly_path: PathStr, output_tree: PathStr, src_tree: PathStr, root_output_in_tree: PathStr
) -> list[PathStr]:
    incbin_paths = parse_incbin(assembly_path)
    if len(incbin_paths) == 0:
        return []
    working_directory = _get_working_directory(incbin_paths[0], output_tree, src_tree, root_output_in_tree)
    if working_directory is None:
        sbom_errors.log(
            f"Skip children of node {root_output_in_tree} because no working directory for {incbin_paths[0]} could be found"
        )
        return []
    return [os.path.normpath(os.path.join(working_directory, incbin_path)) for incbin_path in incbin_paths]


def iter_cmd_graph(cmd_graph: CmdGraph | CmdGraphNode) -> Iterator[CmdGraphNode]:
    visited: set[PathStr] = set()
    node_stack: list[CmdGraphNode] = cmd_graph.roots.copy() if isinstance(cmd_graph, CmdGraph) else [cmd_graph]
    while len(node_stack) > 0:
        node = node_stack.pop(0)
        if node.absolute_path in visited:
            continue

        visited.add(node.absolute_path)
        node_stack = node.children + node_stack
        yield node


def save_cmd_graph(node: CmdGraph, path: PathStr) -> None:
    with open(path, "wb") as f:
        pickle.dump(node, f)


def load_cmd_graph(path: PathStr) -> CmdGraph:
    with open(path, "rb") as f:
        return pickle.load(f)


def build_or_load_cmd_graph(
    root_paths: list[PathStr], output_tree: PathStr, src_tree: PathStr, cmd_graph_path: PathStr
) -> CmdGraph:
    if os.path.exists(cmd_graph_path):
        logging.info("Load cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
    else:
        logging.info("Build cmd graph")
        cmd_graph = build_cmd_graph(root_paths, output_tree, src_tree)
        save_cmd_graph(cmd_graph, cmd_graph_path)
    return cmd_graph


def _to_cmd_path(path: PathStr) -> PathStr:
    name = os.path.basename(path)
    return path.removesuffix(name) + f".{name}.cmd"


def _get_working_directory(
    input_file: PathStr, output_tree: PathStr, src_tree: PathStr, root_artifact: PathStr
) -> PathStr | None:
    """
    Input paths in .cmd files are often relative paths but it is unclear to which original working directory these paths are relative to.
    This function heuristically estimates the working directory for a given input_file and returns the working directory relative to the output tree.
    """

    relative_to_cmd_file = os.path.exists(os.path.join(output_tree, os.path.dirname(root_artifact), input_file))
    relative_to_output_tree = os.path.exists(os.path.join(output_tree, input_file))
    relative_to_tools_objtool = root_artifact.startswith("tools/objtool/arch/x86")
    relative_to_tools_lib_subcmd = root_artifact.startswith("tools/objtool/libsubcmd")

    if relative_to_cmd_file:
        return os.path.dirname(root_artifact)
    elif relative_to_output_tree:
        return "."
    elif relative_to_tools_objtool:
        # Input path relative to `tools/objtool` (e.g., `tools/objtool/arch/x86/special.o` has input `arch/x86/special.c`)
        return os.path.join(os.path.relpath(src_tree, output_tree), "tools/objtool")
    elif relative_to_tools_lib_subcmd:
        # Input path relative to `tools/lib/subcmd` (e.g., `tools/objtool/libsubcmd/.sigchain.o` has input `subcmd-util.h` which lives in `tools/lib/subcmd/subcmd-util.h`)
        return os.path.join(os.path.relpath(src_tree, output_tree), "tools/lib/subcmd")

    return None


def _expand_resolve_files(input_files: list[PathStr], output_tree: PathStr) -> list[PathStr]:
    expanded_input_files: list[PathStr] = []
    for input_file in input_files:
        input_file_str = str(input_file)
        if not input_file_str.startswith("@"):
            expanded_input_files.append(input_file)
            continue
        with open(os.path.join(output_tree, input_file_str[1:]), "r") as f:
            resolve_file_content = [line.strip() for line in f.readlines() if line.strip()]
        expanded_input_files += _expand_resolve_files(resolve_file_content, output_tree)
    return expanded_input_files
