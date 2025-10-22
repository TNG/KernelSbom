#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import asdict, dataclass
from itertools import chain
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

from sbom.cmd.cmd_graph import build_cmd_graph, CmdGraphNode, build_or_load_cmd_graph, iter_cmd_graph  # noqa: E402

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
    cmd_graphs: list[CmdGraphNode],
    filter_patterns: list[re.Pattern[str]] = [],
    missing_files: set[Path] = set(),
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
    for root_node_index, cmd_graph in enumerate(cmd_graphs):
        traverse(cmd_graph, root_node_index)

    return ForceGraph(nodes, links)


def _to_sparse_cmd_graph(
    cmd_graph: CmdGraphNode, include: set[Path], added_before: dict[Path, bool] = {}
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
    cmd_graph: CmdGraphNode,
    output_tree: Path,
    missing_files: set[Path],
    cmd_patterns_to_check: list[str] = ["*.cmd"],
) -> list[CmdGraphNode]:
    """
    Extends an existing cmd graph based on all cmd files in the output tree that are not already present in the cmd graph
    A new graph is spanned.
    """
    cmd_graphs: list[CmdGraphNode] = [cmd_graph]

    cmd_graph_node_cache: dict[Path, CmdGraphNode] = {}
    for node in iter_cmd_graph(cmd_graph):
        cmd_graph_node_cache[node.absolute_path] = node

    # remove children of original cmd graph since those are definitely no missing files
    cmd_graph.children = []

    for cmd_file_path in chain.from_iterable(output_tree.rglob(pattern) for pattern in cmd_patterns_to_check):
        file_path_abs = cmd_file_path.parent / cmd_file_path.name.removeprefix(".").removesuffix(".cmd")
        if file_path_abs in cmd_graph_node_cache.keys():
            continue
        new_graph = build_cmd_graph(
            root_output_in_tree=file_path_abs.relative_to(output_tree),
            output_tree=output_tree,
            src_tree=src_tree,
            cache=cmd_graph_node_cache,
            log_depth=0,
        )

        # check if new_graph includes any missing files. If so add it as new root.
        node_stack: list[CmdGraphNode] = [new_graph]
        root_node_paths = [node.absolute_path for node in cmd_graphs]
        while len(node_stack) > 0:
            node = node_stack.pop(0)
            contains_missing_file = any(node.absolute_path == file for file in missing_files)
            is_root = node.absolute_path in root_node_paths
            if contains_missing_file or is_root:
                logging.info(f"Adding {new_graph.absolute_path} as new root")
                cmd_graphs.append(new_graph)
                break
            node_stack = node.children + node_stack
    return cmd_graphs


def _to_missing_files_graph(
    cmd_graph: CmdGraphNode, output_tree: Path, script_path: Path, config: str
) -> tuple[list[CmdGraphNode], set[Path]]:
    with open(
        script_path / f"../cmd_graph_based_kernel_build/missing_sources/missing_sources_in_cmd_graph.{config}.json",
        "rt",
    ) as f:
        missing_files: set[Path] = set(src_tree / path for path in json.load(f))

    logging.info("Extend Graph based on missing files")
    cmd_graphs = _extend_cmd_graph_with_missing_files(cmd_graph, output_tree, missing_files)

    # list remaining missing files that could not be found
    found_files = {
        node.absolute_path
        for graph in cmd_graphs
        for node in iter_cmd_graph(graph)
        if node.absolute_path in missing_files
    }
    # print("missing files: ", ",\n".join([str(f) for f in found_files]))
    logging.info(f"Found {len(found_files)} of {len(missing_files)} missing files")
    if len(found_files) < len(missing_files):
        remaining_missing_files = sorted([str(f) for f in missing_files if f not in found_files])
        remaining_missing_files_path = script_path / "remaining_missing_files.json"
        with open(remaining_missing_files_path, "wt") as f:
            json.dump(remaining_missing_files, f, indent=2)
        logging.info(f"Saved remaining missing files in {remaining_missing_files_path}")

    # Thin out cmd graph to only show missing files. "bzImage" as first root should still remain
    cmd_graphs = [
        sparse_root_node
        for root_node in cmd_graphs
        if (sparse_root_node := _to_sparse_cmd_graph(root_node, include=missing_files | {cmd_graphs[0].absolute_path}))
        is not None
    ]
    return cmd_graphs, missing_files


if __name__ == "__main__":
    """
    cmd_graph_visualization.py <src_tree> <output_tree>
    """
    script_path = Path(__file__).parent
    src_tree = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) >= 2 and sys.argv[1]
        else (script_path / "../../../linux").resolve()
    )
    output_tree = (
        Path(sys.argv[1]).resolve() if len(sys.argv) >= 3 and sys.argv[2] else (src_tree / "kernel_build").resolve()
    )
    root_output_in_tree = Path("arch/x86/boot/bzImage")
    cmd_graph_path = (script_path / "../cmd_graph.pickle").resolve()

    # missing file graph options
    visualize_missing_files = True
    config = "linux.v6.17.tinyconfig"

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Load cached command graph if available, otherwise build it from .cmd files
    cmd_graph = build_or_load_cmd_graph(root_output_in_tree, output_tree, src_tree, cmd_graph_path)
    cmd_graphs = [cmd_graph]

    # Extend cmd graph with missing files
    missing_files: set[Path] = set()
    if visualize_missing_files:
        cmd_graphs, missing_files = _to_missing_files_graph(cmd_graph, output_tree, script_path, config)

    # Create Force Graph representation
    force_graph = _to_force_graph(
        cmd_graphs,
        filter_patterns=[
            # re.compile(r"^(?!.*voffset\.h$).+\.h$"),  # uncomment if header files make the graph too messy
        ],
        missing_files=missing_files,
    )
    logging.info(f"Found {len(force_graph.nodes)} nodes in {len(cmd_graphs)} roots")

    # Save json data
    data_dict = asdict(force_graph)
    cmd_graph_json_path = (
        script_path / "web" / ("cmd_graph" if not visualize_missing_files else "missing_files_graph") / "cmd_graph.json"
    )
    if len(data_dict) < 100000:
        with open(cmd_graph_json_path, "wt") as f:
            json.dump(data_dict, f, indent=2)
        logging.info(f"Successfully Saved {cmd_graph_json_path}")
    else:
        with gzip.open(f"{cmd_graph_json_path}.gz", "wt", encoding="utf-8") as f:
            json.dump(data_dict, f)
        logging.info(f"Successfully Saved {cmd_graph_json_path}.gz")
