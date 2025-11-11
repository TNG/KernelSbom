#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import json
import logging
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Literal

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from build_kernel import build_kernel  # noqa: E402
from sbom.path_utils import PathStr, is_relative_to  # noqa: E402
from sbom.cmd.cmd_graph import build_or_load_cmd_graph, iter_cmd_graph  # noqa: E402


def _remove_files(base_path: PathStr, patterns_to_remove: list[re.Pattern[str]], ignore: set[PathStr]) -> list[PathStr]:
    removed_files: list[PathStr] = []
    for file_path in [str(p) for p in Path(base_path).rglob("*")]:
        if (
            not os.path.isfile(file_path)
            or os.path.relpath(file_path, base_path) in ignore
            or not any(p.match(file_path) for p in patterns_to_remove)
        ):
            continue

        os.remove(file_path)
        removed_files.append(file_path)
    return removed_files


def _create_cmd_graph_based_kernel_directory(
    src_tree: PathStr,
    output_tree: PathStr,
    cmd_src_tree: PathStr,
    cmd_output_tree: PathStr,
    root_paths: list[PathStr],
    cmd_graph_path: PathStr,
    missing_sources_in_cmd_graph: list[PathStr],
) -> None:
    logging.info(f"Copy {src_tree} into {cmd_src_tree}")
    shutil.copytree(
        src_tree, cmd_src_tree, symlinks=True, ignore=shutil.ignore_patterns(os.path.relpath(output_tree, src_tree))
    )
    os.makedirs(cmd_output_tree, exist_ok=True)
    shutil.copyfile(os.path.join(output_tree, ".config"), os.path.join(cmd_output_tree, ".config"))

    # Load cached command graph or build it from .cmd files
    cmd_graph = build_or_load_cmd_graph(root_paths, output_tree, src_tree, cmd_graph_path)

    # remove source files not in cmd_graph
    source_patterns = [
        re.compile(r".*\.c$"),
        re.compile(r".*\.h$"),
        re.compile(r".*\.S$"),
        re.compile(r".*\.rs$"),
    ]
    logging.info("Extract source files from cmd graph")
    src_tree_str = str(src_tree)
    output_tree_str = str(output_tree)
    cmd_graph_sources = [
        os.path.relpath(node.absolute_path, src_tree_str)
        for node in iter_cmd_graph(cmd_graph)
        if is_relative_to(node.absolute_path, src_tree_str) and not is_relative_to(node.absolute_path, output_tree_str)
    ]

    logging.info("Remove source files not in cmd graph")
    _remove_files(
        cmd_src_tree,
        patterns_to_remove=source_patterns,
        ignore=set(cmd_graph_sources + missing_sources_in_cmd_graph),
    )


def _get_manual_missing_sources(config: Literal["tinyconfig"]) -> list[PathStr]:
    missing_sources = {
        "tinyconfig": [
            "tools/include/linux/types.h",
            "tools/include/linux/kernel.h",
        ]
    }
    return missing_sources[config]


if __name__ == "__main__":
    """
    cmd_graph_based_kernel_build.py <src_tree> <output_tree>
    """
    script_path = os.path.dirname(__file__)
    src_tree = (
        os.path.normpath(sys.argv[1])
        if len(sys.argv) >= 2 and sys.argv[1]
        else os.path.normpath(os.path.join(script_path, "../../../linux"))
    )
    output_tree = (
        os.path.normpath(sys.argv[1]) if len(sys.argv) >= 3 and sys.argv[2] else os.path.join(src_tree, "kernel_build")
    )
    os.environ["SRCARCH"] = "x86"
    root_paths = [
        "arch/x86/boot/bzImage",
    ]
    cmd_graph_path = os.path.normpath(os.path.join(script_path, "../cmd_graph.pickle"))

    cmd_src_tree = f"{src_tree}_cmd"
    cmd_output_tree = os.path.normpath(os.path.join(cmd_src_tree, os.path.relpath(output_tree, src_tree)))
    missing_sources_in_cmd_graph_path = os.path.join(script_path, "missing_sources_in_cmd_graph.json")

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # missing files that need to be added manually because corresponding error messages are difficult to parse:
    missing_sources_in_cmd_graph: list[PathStr] = _get_manual_missing_sources(config="tinyconfig")
    if os.path.exists(missing_sources_in_cmd_graph_path):
        with open(missing_sources_in_cmd_graph_path, "r") as f:
            missing_sources_in_cmd_graph += json.load(f)

    if not os.path.exists(cmd_src_tree):
        _create_cmd_graph_based_kernel_directory(
            src_tree,
            output_tree,
            cmd_src_tree,
            cmd_output_tree,
            root_paths,
            cmd_graph_path,
            missing_sources_in_cmd_graph,
        )
    build_kernel(
        missing_sources_in_cmd_graph,
        cmd_src_tree,
        cmd_output_tree,
        src_tree,
        output_tree,
        missing_sources_in_cmd_graph_path,
    )
