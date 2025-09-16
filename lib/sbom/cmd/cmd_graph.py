#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2025: Luis Augenstein <luis.augenstein@tngtech.com>.

import os
import re
import logging
from pathlib import Path
from dataclasses import dataclass, field
from cmd.savedcmd_parser import parse_savedcmd
from cmd.cmd_file_parser import CmdFile, parse_cmd_file

LD_PATTERN = re.compile(r'(^|\s)ld\b')

@dataclass
class CmdGraphNode():
    cmd_file: CmdFile
    children: list['CmdGraphNode'] = field(default_factory=list)

def _to_cmd(path: Path) -> Path:
    return os.path.join(path.parent, f".{path.name}.cmd")

def build_cmd_graph(root_output_path: Path, cache: dict[str, CmdGraphNode] = None) -> CmdGraphNode:
    """
    Recursively builds a command dependency graph starting from root_output_path.  
    Assumes that for the file at root_output_path a corresponding '.<root_output_path.name>.cmd' file exists.

    Args:
        root_output_path (Path): Path to the root output file.
        cache (dict, optional): Tracks processed nodes to prevent cycles.

    Returns:
        CmdGraphNode: Root of the command dependency graph.

    Raises:
        NotImplementedError: If no parser matches the command.
        CommandParserException: If parsing fails inside a matched parser.
    """
    if cache is None:
        cache = {}

    cmd_file_path = Path(os.path.realpath(_to_cmd(root_output_path)))
    if cmd_file_path in cache:
        # temporary to check if we have any circles in the graph
        raise Exception(f"path {cmd_file_path} was already processed in the cmd graph.")
    
    cmd_file = parse_cmd_file(cmd_file_path)
    node = CmdGraphNode(cmd_file=cmd_file)
    logging.debug(f"Node {cmd_file_path} was created successfully.")
    cache[cmd_file_path] = node

    input_files = parse_savedcmd(cmd_file.savedcmd)
    for input_file in input_files:
        child_path = Path(os.path.join(root_output_path.parent, input_file))
        child_node = build_cmd_graph(child_path)
        node.children.append(child_node)

    return node

def pretty_print_cmd_graph(node: CmdGraphNode, indent=0) -> str:
    lines = []
    lines.append("  " * indent + node.cmd_file.cmd_file_path.name)
    for child in node.children:
        lines.append(pretty_print_cmd_graph(child, indent + 1))
    return "\n".join(lines)