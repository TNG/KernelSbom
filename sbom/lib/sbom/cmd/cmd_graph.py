# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


import logging
import os
from pathlib import Path
from dataclasses import dataclass, field
import pickle
from typing import Iterator

from sbom.cmd.deps_parser import parse_deps
from sbom.cmd.savedcmd_parser import parse_commands
from sbom.cmd.cmd_file_parser import CmdFile, parse_cmd_file
import sbom.errors as sbom_errors
from .hardcoded_dependencies import get_hardcoded_dependencies


@dataclass
class CmdGraphNode:
    absolute_path: Path
    cmd_file: CmdFile | None = None
    children: list["CmdGraphNode"] = field(default_factory=list["CmdGraphNode"])


def build_cmd_graph(
    root_output_in_tree: Path,
    output_tree: Path,
    src_tree: Path,
    cache: dict[Path, CmdGraphNode] | None = None,
    depth: int = 0,
    log_depth: int = 3,
) -> CmdGraphNode:
    """
    Recursively builds a dependency graph starting from `root_output_in_tree` by
    parsing its corresponding `.<root_output_in_tree.name>.cmd` file to discover and follow dependencies.

    Args:
        root_output_in_tree (Path): Path to the root output file relative to output_tree.
        output_tree (Path): absolute Path to the base directory of the output tree.
        src_tree (Path): absolute Path to the `linux` source directory.
        cache (dict | None): Tracks processed nodes to prevent cycles.
        depth (int): Internal parameter to track the current recursion depth.
        log_depth (int): Maximum recursion depth up to which info-level messages are logged.

    Returns:
        CmdGraphNode: Root of the command dependency graph.
    """
    if cache is None:
        cache = {}

    root_output_absolute = Path(os.path.realpath(output_tree / root_output_in_tree))
    if root_output_absolute in cache.keys():
        if depth <= log_depth:
            logging.info(f"Reuse Node: {'  ' * depth}{root_output_in_tree}")
        return cache[root_output_absolute]

    if depth <= log_depth:
        logging.info(f"Build Node: {'  ' * depth}{root_output_in_tree}")
    cmd_path = _to_cmd_path(root_output_absolute)
    cmd_file = parse_cmd_file(cmd_path) if cmd_path.exists() else None
    node = CmdGraphNode(root_output_absolute, cmd_file)
    cache[root_output_absolute] = node

    # find referenced files from current root
    child_paths: list[Path] = get_hardcoded_dependencies(root_output_absolute, output_tree, src_tree)
    if cmd_file is not None:
        child_paths += _get_cmd_file_dependencies(cmd_file, output_tree, src_tree, root_output_in_tree)

    # create child nodes
    for child_path in child_paths:
        child_node = build_cmd_graph(child_path, output_tree, src_tree, cache, depth + 1, log_depth)
        node.children.append(child_node)

    return node


def _get_cmd_file_dependencies(
    cmd_file: CmdFile, output_tree: Path, src_tree: Path, root_output_in_tree: Path
) -> list[Path]:
    # search for input files
    input_files = parse_commands(cmd_file.savedcmd)
    if cmd_file.deps:
        input_files += parse_deps(cmd_file.deps)
    input_files = _expand_resolve_files(input_files, output_tree)
    if len(input_files) == 0:
        return []

    # turn input files to valid child paths relative to output tree
    absolute_inputs = [input for input in input_files if os.path.isabs(input)]
    child_paths = [Path(os.path.relpath(input_file, output_tree)) for input_file in absolute_inputs]
    relative_inputs = [input for input in input_files if not os.path.isabs(input)]
    if len(relative_inputs) > 0:
        # define working directory relative to output_tree which is the directory from which the savedcommand was executed. All input_files should be relative to this working directory.
        # TODO: find a way to parse this directly from the cmd file. For now we estimate the working directory by searching where the first input file lives.
        working_directory = _get_working_directory(relative_inputs[0], output_tree, src_tree, root_output_in_tree)
        if working_directory is None:
            sbom_errors.log(
                f"Skip children of node {root_output_in_tree} because no working directory for relative input {relative_inputs[0]} could be found"
            )
            return []
        child_paths += [Path(os.path.normpath(working_directory / input_file)) for input_file in relative_inputs]

    # some multi stage commands create an output and then pass it as input to the next command for postprocessing, e.g., objcopy.
    # remove generated output from the input_files to prevent nodes from being their own children.
    child_paths = [child_path for child_path in child_paths if child_path != root_output_in_tree]

    return child_paths


def iter_cmd_graph(cmd_graph: CmdGraphNode) -> Iterator[CmdGraphNode]:
    visited: set[Path] = set()
    node_stack: list[CmdGraphNode] = [cmd_graph]
    while len(node_stack) > 0:
        node = node_stack.pop(0)
        if node.absolute_path in visited:
            continue

        visited.add(node.absolute_path)
        node_stack = node.children + node_stack
        yield node


def save_cmd_graph(node: CmdGraphNode, path: Path) -> None:
    with open(path, "wb") as f:
        pickle.dump(node, f)


def load_cmd_graph(path: Path) -> CmdGraphNode:
    with open(path, "rb") as f:
        return pickle.load(f)


def build_or_load_cmd_graph(
    root_output_in_tree: Path, output_tree: Path, src_tree: Path, cmd_graph_path: Path
) -> CmdGraphNode:
    if cmd_graph_path.exists():
        logging.info("Load cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
    else:
        logging.info("Build cmd graph")
        cmd_graph = build_cmd_graph(root_output_in_tree, output_tree, src_tree)
        save_cmd_graph(cmd_graph, cmd_graph_path)
    return cmd_graph


def _to_cmd_path(path: Path) -> Path:
    return path.parent / f".{path.name}.cmd"


def _get_working_directory(
    input_file: Path, output_tree: Path, src_tree: Path, root_output_in_tree: Path
) -> Path | None:
    # Input paths in .cmd files are often relative paths but it is unclear to which original working directory these paths are relative to.
    # This function estimates the working directory based on the location of one input_file and various heuristics.

    relative_to_cmd_file = (output_tree / root_output_in_tree.parent / input_file).exists()
    relative_to_output_tree = (output_tree / input_file).exists()
    relative_to_tools_objtool = str(root_output_in_tree).startswith("tools/objtool/arch/x86")
    relative_to_tools_lib_subcmd = str(root_output_in_tree).startswith("tools/objtool/libsubcmd")

    if relative_to_cmd_file:
        return root_output_in_tree.parent
    elif relative_to_output_tree:
        return Path(".")
    elif relative_to_tools_objtool:
        # Input path relative to `tools/objtool` (e.g., `tools/objtool/arch/x86/special.o` has input `arch/x86/special.c`)
        return Path(os.path.relpath(src_tree, output_tree)) / "tools/objtool"
    elif relative_to_tools_lib_subcmd:
        # Input path relative to `tools/lib/subcmd` (e.g., `tools/objtool/libsubcmd/.sigchain.o` has input `subcmd-util.h` which lives in `tools/lib/subcmd/subcmd-util.h`)
        return Path(os.path.relpath(src_tree, output_tree)) / "tools/lib/subcmd"

    return None


def _expand_resolve_files(input_files: list[Path], output_tree: Path) -> list[Path]:
    expanded_input_files: list[Path] = []
    for input_file in input_files:
        input_file_str = str(input_file)
        if not input_file_str.startswith("@"):
            expanded_input_files.append(input_file)
            continue
        with open(output_tree / input_file_str[1:], "r") as f:
            resolve_file_content = [Path(line.strip()) for line in f.readlines() if line.strip()]
        expanded_input_files += _expand_resolve_files(resolve_file_content, output_tree)
    return expanded_input_files
