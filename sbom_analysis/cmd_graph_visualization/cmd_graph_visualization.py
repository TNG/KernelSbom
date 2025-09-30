#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

from dataclasses import asdict, dataclass
import json
import logging
import os
import sys
from pathlib import Path
import gzip
import re

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd.cmd_graph import build_cmd_graph, CmdGraphNode, load_cmd_graph, save_cmd_graph  # noqa: E402

ForceGraphNodeId = str


@dataclass
class ForceGraphNode:
    id: ForceGraphNodeId
    depth: int


@dataclass
class ForceGraphLink:
    source: ForceGraphNodeId
    target: ForceGraphNodeId


@dataclass
class ForceGraph:
    nodes: list[ForceGraphNode]
    links: list[ForceGraphLink]


def _cmd_graph_to_force_graph(
    cmd_graph: CmdGraphNode, max_depth: int | None = None, filter_patterns: list[re.Pattern[str]] = []
) -> ForceGraph:
    nodes: list[ForceGraphNode] = []
    links: list[ForceGraphLink] = []

    # Keep track of visited nodes by their id to avoid duplicates
    visited: set[ForceGraphNodeId] = set()

    def traverse(node: CmdGraphNode, depth: int = 0):
        node_id = str(node.absolute_path)
        if node_id not in visited:
            nodes.append(ForceGraphNode(id=node_id, depth=depth))
            visited.add(node_id)

        if max_depth is not None and depth > max_depth:
            return

        for child in node.children:
            child_id = str(child.absolute_path)
            if any(pattern.search(child_id) for pattern in filter_patterns):
                continue
            links.append(ForceGraphLink(source=node_id, target=child_id))
            traverse(child, depth + 1)

    traverse(cmd_graph)

    return ForceGraph(nodes, links)


if __name__ == "__main__":
    script_path = Path(__file__).parent
    cmd_graph_path = script_path / "cmd_graph.pickle"
    src_tree = (script_path / "../../linux").resolve()
    output_tree = (script_path / "../../linux/kernel_build").resolve()
    root_output_in_tree = Path("vmlinux")
    cmd_graph_json_gz_path = script_path / "web/cmd_graph.json.gz"
    max_visualization_depth: int | None = None

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Load cached command graph if available, otherwise build it from .cmd files
    if cmd_graph_path.exists():
        logging.info("Loading cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
    else:
        cmd_graph = build_cmd_graph(root_output_in_tree, output_tree, src_tree)
        save_cmd_graph(cmd_graph, cmd_graph_path)

    # Create Force Graph representation
    force_graph = _cmd_graph_to_force_graph(
        cmd_graph,
        max_depth=max_visualization_depth,
        filter_patterns=[re.compile(r"\.h$"), re.compile(r"^.*/include/config/")],
    )
    logging.info(f"Found {len(force_graph.nodes)} nodes.")

    # Save json data
    data_dict = asdict(force_graph)
    with gzip.open(cmd_graph_json_gz_path, "wt", encoding="utf-8") as f:
        json.dump(data_dict, f)

    logging.info(f"Successfully Saved {cmd_graph_json_gz_path}.")
