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

from sbom.cmd.cmd_graph import build_cmd_graph, CmdGraphNode, build_or_load_cmd_graph  # noqa: E402

ForceGraphNodeId = str


@dataclass
class ForceGraphNode:
    id: ForceGraphNodeId
    depth: int
    root_node_index: int


@dataclass
class ForceGraphLink:
    source: ForceGraphNodeId
    target: ForceGraphNodeId


@dataclass
class ForceGraph:
    nodes: list[ForceGraphNode]
    links: list[ForceGraphLink]


def _to_force_graph(
    cmd_graphs: list[CmdGraphNode], max_depth: int | None = None, filter_patterns: list[re.Pattern[str]] = []
) -> ForceGraph:
    nodes: list[ForceGraphNode] = []
    links: list[ForceGraphLink] = []

    # Keep track of visited nodes by their id to avoid duplicates
    visited: set[ForceGraphNodeId] = set()

    def traverse(node: CmdGraphNode, root_node_index: int, depth: int = 0):
        node_id = str(node.absolute_path)
        if node_id in visited:
            return

        nodes.append(ForceGraphNode(id=node_id, depth=depth, root_node_index=root_node_index))
        visited.add(node_id)

        if max_depth is not None and depth > max_depth:
            return

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


def _cmd_graph_to_node_dict(
    node: CmdGraphNode, node_dict: dict[Path, CmdGraphNode] | None = None
) -> dict[Path, CmdGraphNode]:
    if node_dict is None:
        node_dict = {}
    node_dict[node.absolute_path] = node
    for child in node.children:
        _cmd_graph_to_node_dict(child, node_dict)
    return node_dict


def _to_sparse_cmd_graph(cmd_graph: CmdGraphNode, include: set[Path]) -> CmdGraphNode | None:
    """Returns a thinned out cmd graph where all nodes are removed that contain none of the include files below"""
    if len(cmd_graph.children) == 0:
        return cmd_graph if cmd_graph.absolute_path in include else None

    sparse_children: list[CmdGraphNode] = []
    for child_node in cmd_graph.children:
        sparse_child = _to_sparse_cmd_graph(child_node, include)
        if sparse_child:
            sparse_children.append(sparse_child)

    if len(sparse_children) == 0:
        return None

    cmd_graph.children = sparse_children
    return cmd_graph


def _extend_cmd_graph_with_missing_files(
    cmd_graph: CmdGraphNode,
    output_tree: Path,
    missing_files: set[Path],
    cmd_patterns_to_check: list[str] = ["*.o.cmd", "*.a.cmd"],
) -> tuple[list[CmdGraphNode], set[Path]]:
    """
    Extends an existing cmd graph based on all cmd files in the output tree that are not already in the cmd_graph_node_cache.
    A new graph is spanned.
    """
    found_files: set[Path] = set()
    cmd_graphs: list[CmdGraphNode] = [cmd_graph]
    cmd_graph_node_cache = _cmd_graph_to_node_dict(cmd_graph)
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
        child_queue: list[CmdGraphNode] = [new_graph]
        while len(child_queue) > 0:
            node = child_queue.pop(0)
            root_files = set(node.absolute_path for node in cmd_graphs)
            found_files_in_node = {file for file in missing_files if file == node.absolute_path}
            if len(found_files_in_node) > 0 or node.absolute_path in root_files:
                # found missing file or other root node in children of new_graph
                found_files = found_files | found_files_in_node
                logging.info(
                    f"Found parent: {node.absolute_path} of missing files {found_files_in_node}. Adding {new_graph.absolute_path} as new root"
                )
                cmd_graphs.append(new_graph)
                break
            child_queue += node.children
        if cmd_graphs[-1] != new_graph:
            logging.info(f"No missing file found in children of {new_graph.absolute_path}")
    return cmd_graphs, found_files


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
    root_output_in_tree = Path("vmlinux")
    cmd_graph_path = (script_path / "../cmd_graph.pickle").resolve()

    cmd_graph_json_gz_path = script_path / "web/cmd_graph.json.gz"
    max_visualization_depth: int | None = None
    visualize_missing_files = True
    remaining_missing_files_path = script_path / "remaining_missing_files.json"
    config = "linux.v6.17.tinyconfig"

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Load cached command graph if available, otherwise build it from .cmd files
    cmd_graph = build_or_load_cmd_graph(root_output_in_tree, output_tree, src_tree, cmd_graph_path)

    # Extend cmd graph with missing files
    with open(
        script_path / f"../cmd_graph_based_kernel_build/missing_sources/missing_sources_in_cmd_graph.{config}.json",
        "rt",
    ) as f:
        missing_files: set[Path] = set(src_tree / path for path in json.load(f))

    logging.info("Extend Graph based on missing files")
    cmd_graphs, found_files = _extend_cmd_graph_with_missing_files(cmd_graph, output_tree, missing_files)

    # list remaining missing files that could not be found
    logging.info(f"Found {len(found_files)} of {len(missing_files)} missing files")
    if len(found_files) < len(missing_files):
        remaining_missing_files = [f for f in missing_files if f not in found_files]
        with open(remaining_missing_files_path, "wt") as f:
            json.dump([str(p) for p in remaining_missing_files], f, indent=2)
        logging.info(f"Saved remaining missing files in {remaining_missing_files_path}")

    # Thin out cmd graph to only show missing files. "vmlinux" as first root should still remain
    # missing_files.remove(src_tree / "arch/x86/include/uapi/asm/stat.h")
    # missing_files.remove(src_tree / "include/linux/dma-mapping.h")

    cmd_graphs = [
        root_node
        for root_node in cmd_graphs
        if (sparse_root_node := _to_sparse_cmd_graph(root_node, include=missing_files | {cmd_graphs[0].absolute_path}))
        is not None
    ]

    # Create Force Graph representation
    force_graph = _to_force_graph(
        cmd_graphs,
        max_depth=max_visualization_depth,
        filter_patterns=[
            # re.compile(r"\.h$"),
            re.compile(r"^.*/include/config/"),
        ],
    )
    logging.info(f"Found {len(force_graph.nodes)} nodes in {len(cmd_graphs)} roots")

    # Save json data
    data_dict = asdict(force_graph)
    cmd_graph_json_path = (
        script_path
        / "web"
        / ("vmlinux" if not visualize_missing_files else "vmlinux_with_missing_files")
        / "cmd_graph.json"
    )
    if len(data_dict) < 100000:
        with open(cmd_graph_json_path, "wt") as f:
            json.dump(data_dict, f, indent=2)
        logging.info(f"Successfully Saved {cmd_graph_json_path}")
    else:
        with gzip.open(f"{cmd_graph_json_path}.gz", "wt", encoding="utf-8") as f:
            json.dump(data_dict, f)
        logging.info(f"Successfully Saved {cmd_graph_json_path}.gz")
