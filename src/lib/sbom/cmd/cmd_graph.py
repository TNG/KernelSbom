# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only


import logging
import os
from pathlib import Path
from dataclasses import dataclass, field
from .savedcmd_parser import parse_savedcmd
from .cmd_file_parser import CmdFile, parse_cmd_file


@dataclass
class CmdGraphNode:
    absolute_path: Path
    cmd_file: CmdFile | None
    children: list["CmdGraphNode"] = field(default_factory=list["CmdGraphNode"])


def _to_cmd_path(path: Path) -> Path:
    return path.parent / f".{path.name}.cmd"


def build_cmd_graph(
    root_output_in_tree: Path, output_tree: Path, cache: dict[Path, CmdGraphNode] | None = None, depth: int = 0
) -> CmdGraphNode:
    """
    Recursively builds a command dependency graph starting from `root_output_in_tree`. <br>
    Assumes that for the given file a corresponding `.<root_output_in_tree.name>.cmd` file exists.

    Args:
        root_output_in_tree (Path): Path to the root output file relative to output_tree.
        output_tree (Path): absolute Path to the base directory of the output_tree.
        cache (dict, optional): Tracks processed nodes to prevent cycles.

    Returns:
        CmdGraphNode: Root of the command dependency graph.
    """
    if cache is None:
        cache = {}

    absolute_path = Path(os.path.realpath(output_tree / root_output_in_tree))
    if absolute_path in cache:
        logging.debug(f"Reuse Node: {absolute_path}")
        return cache[absolute_path]

    logging.debug(f"Build Node: {'  ' * depth}{absolute_path.name}")
    cmd_path = _to_cmd_path(absolute_path)
    cmd_file = parse_cmd_file(cmd_path) if cmd_path.exists() else None
    node = CmdGraphNode(absolute_path, cmd_file)
    cache[absolute_path] = node

    if cmd_file is None:
        return node

    input_files = parse_savedcmd(cmd_file.savedcmd)
    for input_file in input_files:
        # Input paths in .cmd files are inconsistent: some are relative to the output tree root,
        # others are relative to the .cmd file's directory.
        child_path = (
            root_output_in_tree.parent / input_file
            if (output_tree / root_output_in_tree.parent / input_file).exists()
            else Path(input_file)
        )
        child_node = build_cmd_graph(child_path, output_tree, cache, depth + 1)
        node.children.append(child_node)

    return node
