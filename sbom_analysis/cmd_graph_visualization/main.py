#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import asdict, dataclass
import json
import logging
import os
from pathlib import Path
import sys
import gzip
import re

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.path_utils import PathStr  # noqa: E402
from sbom.cmd_graph.cmd_graph import (  # noqa: E402
    build_cmd_graph_node,
    CmdGraphNode,
    CmdGraph,
    build_or_load_cmd_graph,
    iter_cmd_graph,
)

ForceGraphNodeId = str


@dataclass
class ForceGraphNode:
    id: ForceGraphNodeId
    depth: int
    root_node_index: int
    is_missing_file: bool


@dataclass
class ForceGraphLink:
    source: ForceGraphNodeId
    target: ForceGraphNodeId


@dataclass
class ForceGraph:
    nodes: list[ForceGraphNode]
    links: list[ForceGraphLink]


def _to_force_graph(
    cmd_graph: CmdGraph,
    filter_patterns: list[re.Pattern[str]] = [],
    missing_files: set[PathStr] = set(),
) -> ForceGraph:
    nodes: list[ForceGraphNode] = []
    links: list[ForceGraphLink] = []

    # Keep track of visited nodes by their id to avoid duplicates
    visited: set[ForceGraphNodeId] = set()

    def traverse(node: CmdGraphNode, root_node_index: int, depth: int = 0):
        node_id = str(node.absolute_path)
        if node_id in visited:
            return

        nodes.append(
            ForceGraphNode(
                id=node_id,
                depth=depth,
                root_node_index=root_node_index,
                is_missing_file=node.absolute_path in missing_files,
            )
        )
        visited.add(node_id)

        for child in node.children:
            child_id = str(child.absolute_path)
            if any(pattern.search(child_id) for pattern in filter_patterns):
                continue
            links.append(ForceGraphLink(source=child_id, target=node_id))
            traverse(child, root_node_index, depth + 1)

    logging.info("Transforming CMD Graph to Force Graph:")
    for root_node_index, root_node in enumerate(cmd_graph.roots):
        traverse(root_node, root_node_index)

    return ForceGraph(nodes, links)


def _to_sparse_cmd_graph(
    cmd_graph: CmdGraphNode, include: set[PathStr], added_before: dict[PathStr, bool] = {}
) -> CmdGraphNode | None:
    """Returns a thinned out cmd graph where all nodes are removed that contain none of the include files below"""
    if cmd_graph.absolute_path in added_before.keys():
        return cmd_graph if added_before[cmd_graph.absolute_path] else None

    sparse_children: list[CmdGraphNode] = []
    for child_node in cmd_graph.children:
        sparse_child = _to_sparse_cmd_graph(child_node, include, added_before)
        if sparse_child is not None:
            sparse_children.append(sparse_child)

    cmd_graph.children = sparse_children
    if cmd_graph.absolute_path in include or len(sparse_children) > 0:
        added_before[cmd_graph.absolute_path] = True
        return cmd_graph
    added_before[cmd_graph.absolute_path] = False
    return None


def _extend_cmd_graph_with_missing_files(
    cmd_graph: CmdGraph,
    output_tree: PathStr,
    missing_files: set[PathStr],
) -> CmdGraph:
    """
    Extends an existing cmd graph based on all cmd files in the output tree that are not already present in the cmd graph
    A new graph is spanned.
    """
    cmd_graph_node_cache: dict[PathStr, CmdGraphNode] = {}
    for node in iter_cmd_graph(cmd_graph):
        cmd_graph_node_cache[node.absolute_path] = node

    # remove children of original cmd graph roots since those are definitely no missing files
    root_nodes = [CmdGraphNode(root.absolute_path, root.cmd_file) for root in cmd_graph.roots]

    for cmd_file_path in [str(p) for p in Path(output_tree).rglob("*.cmd")]:
        file_path_abs = os.path.join(
            os.path.dirname(cmd_file_path), os.path.basename(cmd_file_path).removeprefix(".").removesuffix(".cmd")
        )
        if file_path_abs in cmd_graph_node_cache.keys():
            continue
        potential_new_root = build_cmd_graph_node(
            root_path=os.path.relpath(file_path_abs, output_tree),
            output_tree=output_tree,
            src_tree=src_tree,
            cache=cmd_graph_node_cache,
            log_depth=0,
        )

        # check if potential_new_root includes any missing files. If so add it as new root.
        node_stack: list[CmdGraphNode] = [potential_new_root]
        while len(node_stack) > 0:
            node = node_stack.pop(0)
            is_missing_file = any(node.absolute_path == file for file in missing_files)
            is_root = any(node.absolute_path == root.absolute_path for root in root_nodes)
            if is_missing_file or is_root:
                logging.info(f"Adding {potential_new_root.absolute_path} as new root")
                root_nodes.append(potential_new_root)
                break
            node_stack = node.children + node_stack
    return CmdGraph(root_nodes)


def _to_missing_files_graph(
    cmd_graph: CmdGraph, output_tree: PathStr, script_path: PathStr, config: str
) -> tuple[CmdGraph, set[PathStr]]:
    with open(
        os.path.join(
            script_path, f"../cmd_graph_based_kernel_build/missing_sources/missing_sources_in_cmd_graph.{config}.json"
        ),
        "rt",
    ) as f:
        missing_files: set[PathStr] = set(os.path.join(src_tree, path) for path in json.load(f))  # type: ignore

    logging.info("Extend Graph based on missing files")
    cmd_graph_with_missing_files = _extend_cmd_graph_with_missing_files(cmd_graph, output_tree, missing_files)

    # list remaining missing files that could not be found
    found_files = {
        node.absolute_path
        for node in iter_cmd_graph(cmd_graph_with_missing_files)
        if node.absolute_path in missing_files
    }
    logging.info(f"Found {len(found_files)} of {len(missing_files)} missing files")
    if len(found_files) < len(missing_files):
        remaining_missing_files = sorted([str(f) for f in missing_files if f not in found_files])
        remaining_missing_files_path = os.path.join(script_path, "remaining_missing_files.json")
        with open(remaining_missing_files_path, "wt") as f:
            json.dump(remaining_missing_files, f, indent=2)
        logging.info(f"Saved remaining missing files in {remaining_missing_files_path}")

    # Thin out cmd graph to only show missing files. "bzImage" as first root should still remain
    original_root_node_paths = {root_node.absolute_path for root_node in cmd_graph.roots}
    sparse_root_nodes = [
        sparse_root_node
        for root_node in cmd_graph_with_missing_files.roots
        if (sparse_root_node := _to_sparse_cmd_graph(root_node, include=missing_files | original_root_node_paths))
        is not None
    ]
    return CmdGraph(sparse_root_nodes), missing_files


if __name__ == "__main__":
    """
    cmd_graph_visualization.py <src_tree> <output_tree>
    """
    script_path = os.path.dirname(__file__)
    src_tree = (
        os.path.realpath(sys.argv[1])
        if len(sys.argv) >= 2 and sys.argv[1]
        else os.path.realpath(os.path.join(script_path, "../../../linux"))
    )
    output_tree = (
        os.path.realpath(sys.argv[2]) if len(sys.argv) >= 3 and sys.argv[2] else os.path.join(src_tree, "kernel_build")
    )
    os.environ["SRCARCH"] = "x86"
    root_paths = [
        "arch/x86/boot/bzImage",
    ]
    cmd_graph_path = os.path.normpath(os.path.join(script_path, "../cmd_graph.pickle"))

    # missing file graph options
    visualize_missing_files = True
    config = "linux.v6.17.tinyconfig"

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Load cached command graph if available, otherwise build it from .cmd files
    cmd_graph = build_or_load_cmd_graph(root_paths, output_tree, src_tree, cmd_graph_path)

    # Extend cmd graph with missing files
    missing_files: set[PathStr] = set()
    if visualize_missing_files:
        cmd_graph, missing_files = _to_missing_files_graph(cmd_graph, output_tree, script_path, config)

    # Create Force Graph representation
    force_graph = _to_force_graph(
        cmd_graph,
        filter_patterns=[
            # re.compile(r"^(?!.*voffset\.h$).+\.h$"),  # uncomment if header files make the graph too messy
        ],
        missing_files=missing_files,
    )
    logging.info(f"Found {len(force_graph.nodes)} nodes in {len(cmd_graph.roots)} roots")

    # Save json data
    data_dict = asdict(force_graph)
    cmd_graph_json_path = os.path.join(
        script_path, "web", ("cmd_graph" if not visualize_missing_files else "missing_files_graph"), "cmd_graph.json"
    )
    if len(data_dict) < 100000:
        with open(cmd_graph_json_path, "wt") as f:
            json.dump(data_dict, f, indent=2)
        logging.info(f"Successfully Saved {cmd_graph_json_path}")
    else:
        with gzip.open(f"{cmd_graph_json_path}.gz", "wt", encoding="utf-8") as f:
            json.dump(data_dict, f)
        logging.info(f"Successfully Saved {cmd_graph_json_path}.gz")
