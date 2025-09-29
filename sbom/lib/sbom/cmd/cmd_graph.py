# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only


import logging
import os
from pathlib import Path
from dataclasses import dataclass, field
import pickle
from typing import Iterator

from .deps_parser import parse_deps
from .savedcmd_parser import parse_commands
from .cmd_file_parser import CmdFile, parse_cmd_file


@dataclass
class CmdGraphNode:
    absolute_path: Path
    cmd_file: CmdFile | None = None
    children: list["CmdGraphNode"] = field(default_factory=list["CmdGraphNode"])


def _to_cmd_path(path: Path) -> Path:
    return path.parent / f".{path.name}.cmd"


def build_cmd_graph(
    root_output_in_tree: Path,
    output_tree: Path,
    src_tree: Path,
    cache: dict[Path, CmdGraphNode] | None = None,
    depth: int = 0,
    log_graph_depth_limit: int = 4,
) -> CmdGraphNode:
    """
    Recursively builds a dependency graph starting from `root_output_in_tree` by
    parsing its corresponding `.<root_output_in_tree.name>.cmd` file to discover and follow dependencies.

    Args:
        root_output_in_tree (Path): Path to the root output file relative to output_tree.
        output_tree (Path): absolute Path to the base directory of the output_tree.
        src_tree (Path): absolute Path to the `linux` source directory.
        cache (dict | None): Tracks processed nodes to prevent cycles.
        depth (int): Internal parameter to track the current recursion depth.
        log_graph_depth_limit (int): Maximum recursion depth up to which info-level messages are logged.

    Returns:
        CmdGraphNode: Root of the command dependency graph.
    """
    if cache is None:
        cache = {}

    root_output_absolute = Path(os.path.realpath(output_tree / root_output_in_tree))
    if root_output_absolute in cache.keys():
        if depth <= log_graph_depth_limit:
            logging.info(f"Reuse Node: {'  ' * depth}{root_output_in_tree}")
        return cache[root_output_absolute]

    if depth <= log_graph_depth_limit:
        logging.info(f"Build Node: {'  ' * depth}{root_output_in_tree}")
    cmd_path = _to_cmd_path(root_output_absolute)
    cmd_file = parse_cmd_file(cmd_path) if cmd_path.exists() else None
    node = CmdGraphNode(root_output_absolute, cmd_file)
    cache[root_output_absolute] = node

    if cmd_file is None:
        return node

    input_files = parse_commands(cmd_file.savedcmd)
    if cmd_file.deps:
        input_files += parse_deps(cmd_file.deps, output_tree)

    if len(input_files) == 0:
        return node

    # define working directory relative to output_tree which is the directory from which the savedcommand was executed. All input_files should be relative to this working directory.
    # TODO: find a way to parse this directly from the cmd file. For now we estimate the working directory by searching where the first input file lives.
    working_directory = _get_working_directory(output_tree, src_tree, root_output_in_tree, input_file=input_files[0])

    for input_file in input_files:
        if os.path.isabs(input_file):
            child_path = Path(os.path.relpath(input_file, output_tree))
        else:
            child_path = working_directory / input_file
        if not (output_tree / child_path).exists():
            raise ValueError(f"root_output_in_tree {child_path} should be relative to output_tree {output_tree}")
        child_node = build_cmd_graph(child_path, output_tree, src_tree, cache, depth + 1, log_graph_depth_limit)
        node.children.append(child_node)

    return node


def _get_working_directory(output_tree: Path, src_tree: Path, root_output_in_tree: Path, input_file: Path) -> Path:
    # Input paths in .cmd files are often relative paths but it is unclear to which original working directory these paths are relative to.
    # This function estimates the working directory based on the location of one input_file and various heuristics.

    relative_to_cmd_file = (output_tree / root_output_in_tree.parent / input_file).exists()
    relative_to_output_tree = (output_tree / input_file).exists()
    relative_to_src_tree = (src_tree / input_file).exists()
    relative_to_source_file = (src_tree / root_output_in_tree.parent / input_file).exists()

    if relative_to_cmd_file:
        return root_output_in_tree.parent
    elif relative_to_output_tree:
        return Path(".")
    elif relative_to_src_tree:
        # Input path relative to the source tree. While .cmd files typically don't reference such paths directly, this case handles .cmd files
        # where inputs are omitted entirely despite depending on source tree files (e.g., `genheaders` command in `security/selinux/.flask.h.cmd` where `security/selinux/genheaders.c` depends on header files that are not specified in the .cmd).
        return Path(os.path.relpath(src_tree, output_tree))
    elif relative_to_source_file:
        # Input path relative to the source file in the source tree. Like the previous case this case does not occur directly in cmd files but may occur
        # when inputs are omitted entirely despite depending on source tree files (e.g., `mkcpustr` command in `arch/x86/boot/.cpustr.h.cmd` hwere `arch/x86/boot/cpustr.h` depends on other .h and .c files that are not specified in the .cmd).
        return Path(os.path.relpath(src_tree / root_output_in_tree.parent, output_tree))

    relative_to_tools_objtool = str(root_output_in_tree).startswith("tools/objtool/arch/x86")
    if relative_to_tools_objtool:
        # Input path relative to `tools/objtool` (e.g., `tools/objtool/arch/x86/special.o` has input `arch/x86/special.c`)
        return Path(os.path.relpath(src_tree, output_tree)) / "tools/objtool"
    relative_to_tools_lib_subcmd = str(root_output_in_tree).startswith("tools/objtool/libsubcmd")
    if relative_to_tools_lib_subcmd:
        # Input path relative to `tools/lib/subcmd` (e.g., `tools/objtool/libsubcmd/.sigchain.o` has input `subcmd-util.h` which lives in `tools/lib/subcmd/subcmd-util.h`)
        return Path(os.path.relpath(src_tree, output_tree)) / "tools/lib/subcmd"

    raise ValueError(f"Cannot resolve input: {input_file} of file for {_to_cmd_path(root_output_in_tree)}")


def save_cmd_graph(node: CmdGraphNode, path: Path) -> None:
    with open(path, "wb") as f:
        pickle.dump(node, f)


def load_cmd_graph(path: Path) -> CmdGraphNode:
    with open(path, "rb") as f:
        return pickle.load(f)


def iter_files_in_cmd_graph(cmd_graph: CmdGraphNode) -> Iterator[Path]:
    yield cmd_graph.absolute_path
    for child_node in cmd_graph.children:
        yield from iter_files_in_cmd_graph(child_node)
