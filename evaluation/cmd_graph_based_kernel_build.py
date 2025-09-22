#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

import logging
import os
import shutil
import sys
from pathlib import Path

LIB_DIR = "../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd.cmd_graph import build_cmd_graph, CmdGraphNode, load_cmd_graph, save_cmd_graph  # noqa: E402


def _is_path_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _copy_cmd_graph_sources(
    cmd_graph: CmdGraphNode,
    output_tree: Path,
    src_tree: Path,
    cmd_src_tree: Path,
    depth: int = 0,
    log_graph_depth_limit: int = 4,
) -> None:
    if _is_path_within(cmd_graph.absolute_path, output_tree):
        if depth <= log_graph_depth_limit:
            logging.info(f"Skip Node: {depth * '  '}{cmd_graph.absolute_path.relative_to(output_tree)}")
    else:
        relative_path = cmd_graph.absolute_path.relative_to(src_tree)
        if depth <= log_graph_depth_limit:
            logging.info(f"Copy Node: {depth * '  '}{relative_path}")
        dest_path = cmd_src_tree / relative_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cmd_graph.absolute_path, dest_path)

    for child_node in cmd_graph.children:
        _copy_cmd_graph_sources(child_node, output_tree, src_tree, cmd_src_tree, depth + 1)


def _copy_additional_build_files(src_tree: Path, cmd_src_tree: Path) -> None:
    patterns = [
        "scripts/**/*",
        "Makefile",
        "Kconfig",
        "Kconfig.*",
        "arch/x86/configs/x86_64_defconfig",
    ]

    for pattern in patterns:
        logging.info(f"Copy {pattern}")
        for file_path in src_tree.rglob(pattern):
            if not file_path.is_file():
                continue
            print(file_path)
            dest_path = cmd_src_tree / file_path.relative_to(src_tree)
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(file_path, dest_path)


def _build_linux_kernel(cmd_src_tree: Path, cmd_output_tree: Path) -> None:
    pass


if __name__ == "__main__":
    # Paths to the original source and build directories
    cmd_graph_path = Path("evaluation/cmd_graph.pickle")
    src_tree = Path("../linux").resolve()
    output_tree = Path("../linux/kernel-build").resolve()
    root_output_in_tree = Path("vmlinux")

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Load cached command graph if available, otherwise build it from .cmd files
    # if cmd_graph_path.exists():
    #     logging.info("Loading cmd graph")
    #     cmd_graph = load_cmd_graph(cmd_graph_path)
    # else:
    #     cmd_graph = build_cmd_graph(root_output_in_tree, output_tree, src_tree)
    #     save_cmd_graph(cmd_graph, cmd_graph_path)

    # Create a new source tree containing only the files referenced in the command graph
    cmd_src_tree = Path("./linux-cmd").resolve()
    # _copy_cmd_graph_sources(cmd_graph, output_tree, src_tree, cmd_src_tree)
    _copy_additional_build_files(src_tree, cmd_src_tree)

    # Copy additional required build files and rebuild the Linux kernel from the reduced source tree
    cmd_output_tree = Path("./linux-cmd/kernel-build").resolve()
    _build_linux_kernel(cmd_src_tree, cmd_output_tree)
