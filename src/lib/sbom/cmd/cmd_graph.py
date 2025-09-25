# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only


import logging
import os
from pathlib import Path
from dataclasses import dataclass, field

from .deps_parser import parse_deps
from .savedcmd_parser import parse_commands
from .cmd_file_parser import CmdFile, parse_cmd_file


@dataclass
class CmdGraphNode:
    absolute_path: Path
    cmd_file: CmdFile | None
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
    Recursively builds a command dependency graph starting from `root_output_in_tree`. <br>
    Assumes that for the given file a corresponding `.<root_output_in_tree.name>.cmd` file exists.

    Args:
        root_output_in_tree (Path): Path to the root output file relative to output_tree.
        output_tree (Path): absolute Path to the base directory of the output_tree.
        src_tree (Path): absolute Path to the `linux` source directory.
        cache (dict, optional): Tracks processed nodes to prevent cycles.
        depth (int): Internal parameter to track the current recursion depth.
        log_graph_depth_limit (int): Maximum recursion depth up to which info-level messages are logged.

    Returns:
        CmdGraphNode: Root of the command dependency graph.
    """
    if cache is None:
        cache = {}

    root_output_absolute = Path(os.path.realpath(output_tree / root_output_in_tree))
    if root_output_in_tree in cache:
        logging.debug(f"Reuse Node: {'  ' * depth}{root_output_in_tree}")
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
    for input_file in input_files:
        # Input paths in .cmd files are inconsistent: some are relative to the .cmd file's directory,
        # others are relative to the output tree root.
        if (output_tree / root_output_in_tree.parent / input_file).exists():
            child_path = root_output_in_tree.parent / input_file
        elif (output_tree / input_file).exists():
            child_path = input_file
        elif (src_tree / input_file).exists():
            # Input paths relative to the source tree. While .cmd files typically don't reference such paths directly, this case handles .cmd files
            # where inputs are omitted entirely despite depending on source tree files (e.g., `genheaders` command in `security/selinux/.flask.h.cmd`).
            child_path = Path(os.path.relpath(src_tree / input_file, output_tree))
        else:
            raise ValueError(f"Cannot resolve path: {input_file}")
        child_node = build_cmd_graph(child_path, output_tree, src_tree, cache, depth + 1)
        node.children.append(child_node)

    return node
