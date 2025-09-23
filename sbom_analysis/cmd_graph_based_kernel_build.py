#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path

LIB_DIR = "../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd.cmd_graph import build_cmd_graph, CmdGraphNode, load_cmd_graph, save_cmd_graph  # noqa: E402


def _get_files_in_cmd_graph(cmd_graph: CmdGraphNode, patterns: list[re.Pattern[str]]) -> list[Path]:
    cmd_graph_files: list[Path] = []
    if any(p.search(str(cmd_graph.absolute_path)) for p in patterns):
        cmd_graph_files.append(cmd_graph.absolute_path)
    for child_node in cmd_graph.children:
        child_graph_files = _get_files_in_cmd_graph(child_node, patterns)
        cmd_graph_files += child_graph_files
    return cmd_graph_files


def _get_files_in_directory(dir: Path, patterns: list[re.Pattern[str]]) -> list[Path]:
    return [
        file_path
        for file_path in dir.rglob("**/*")
        if file_path.is_file() and any(p.match(str(file_path)) for p in patterns)
    ]


def _remove_files(base_path: Path, patterns_to_remove: list[re.Pattern[str]], ignore: set[Path]) -> list[Path]:
    removed_files: list[Path] = []
    for file_path in base_path.rglob("*"):
        if (
            not file_path.is_file()
            or file_path.relative_to(base_path) in ignore
            or not any(p.match(str(file_path)) for p in patterns_to_remove)
        ):
            continue

        logging.info(f"Delete {file_path}")
        file_path.unlink()
        removed_files.append(file_path)
    return removed_files


if __name__ == "__main__":
    # Paths to the original source and build directories
    cmd_graph_path = Path("sbom_analysis/cmd_graph.pickle")
    src_tree = Path("../linux").resolve()
    output_tree = Path("../linux/kernel-build").resolve()
    root_output_in_tree = Path("vmlinux")

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Copy the original source tree
    cmd_src_tree = Path("./linux-cmd").resolve()
    if cmd_src_tree.exists():
        shutil.rmtree(cmd_src_tree)
    logging.info(f"Copy {src_tree} into {cmd_src_tree}")
    shutil.copytree(src_tree, cmd_src_tree, ignore=shutil.ignore_patterns(output_tree.relative_to(src_tree)))

    # Load cached command graph if available, otherwise build it from .cmd files
    if cmd_graph_path.exists():
        logging.info("Load cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
    else:
        cmd_graph = build_cmd_graph(root_output_in_tree, output_tree, src_tree)
        save_cmd_graph(cmd_graph, cmd_graph_path)

    # remove source files not in cmd_graph
    source_patterns = [
        re.compile(r".*\.c$"),
        re.compile(r".*\.h$"),
        re.compile(r".*\.S$"),
    ]
    logging.info("Extract source files from cmd graph")
    cmd_graph_sources = [s.relative_to(src_tree) for s in _get_files_in_cmd_graph(cmd_graph, source_patterns)]
    with open("sbom_analysis/cmd_graph_sources.json", "wt") as f:
        json.dump([str(s) for s in cmd_graph_sources], f)

    additional_sources: list[Path] = [
        s.relative_to(src_tree)
        for s in [
            *_get_files_in_directory(src_tree / "scripts", source_patterns),
            *_get_files_in_directory(src_tree / "tools", source_patterns),
            *_get_files_in_directory(src_tree / "include", source_patterns),
            *_get_files_in_directory(src_tree / "arch/x86", source_patterns),
            *_get_files_in_directory(src_tree / "kernel", source_patterns),
            *_get_files_in_directory(src_tree / "usr", source_patterns),
            *_get_files_in_directory(src_tree / "certs", source_patterns),
            *_get_files_in_directory(src_tree / "fs/efivarfs", source_patterns),
            *_get_files_in_directory(src_tree / "security/selinux", source_patterns),
        ]
    ]
    logging.info("Remove source files not in cmd graph")
    removed_sources = _remove_files(
        cmd_src_tree,
        patterns_to_remove=source_patterns,
        ignore=set(cmd_graph_sources + additional_sources),
    )
    with open("sbom_analysis/removed_sources.json", "wt") as f:
        json.dump([str(s) for s in removed_sources], f)
