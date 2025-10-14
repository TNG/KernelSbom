#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Literal
from build_kernel import build_kernel

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd.cmd_graph import build_or_load_cmd_graph, iter_cmd_graph  # noqa: E402


def _remove_files(base_path: Path, patterns_to_remove: list[re.Pattern[str]], ignore: set[Path]) -> list[Path]:
    removed_files: list[Path] = []
    for file_path in base_path.rglob("*"):
        if (
            not file_path.is_file()
            or file_path.relative_to(base_path) in ignore
            or not any(p.match(str(file_path)) for p in patterns_to_remove)
        ):
            continue

        file_path.unlink()
        removed_files.append(file_path)
    return removed_files


def _create_cmd_graph_based_kernel_directory(
    src_tree: Path,
    output_tree: Path,
    cmd_src_tree: Path,
    cmd_output_tree: Path,
    root_output_in_tree: Path,
    cmd_graph_path: Path,
    missing_sources_in_cmd_graph: list[Path],
) -> None:
    logging.info(f"Copy {src_tree} into {cmd_src_tree}")
    shutil.copytree(
        src_tree, cmd_src_tree, symlinks=True, ignore=shutil.ignore_patterns(output_tree.relative_to(src_tree))
    )
    cmd_output_tree.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output_tree / ".config", cmd_output_tree / ".config")

    # Load cached command graph or build it from .cmd files
    cmd_graph = build_or_load_cmd_graph(root_output_in_tree, output_tree, src_tree, cmd_graph_path)

    # remove source files not in cmd_graph
    source_patterns = [
        re.compile(r".*\.c$"),
        re.compile(r".*\.h$"),
        re.compile(r".*\.S$"),
        re.compile(r".*\.rs$"),
    ]
    logging.info("Extract source files from cmd graph")
    cmd_graph_sources = [
        node.absolute_path.relative_to(src_tree)
        for node in iter_cmd_graph(cmd_graph)
        if node.absolute_path.is_relative_to(src_tree) and not node.absolute_path.is_relative_to(output_tree)
    ]

    logging.info("Remove source files not in cmd graph")
    _remove_files(
        cmd_src_tree,
        patterns_to_remove=source_patterns,
        ignore=set(cmd_graph_sources + missing_sources_in_cmd_graph),
    )


def _get_manual_missing_sources(config: Literal["tinyconfig"]) -> list[Path]:
    missing_sources = {
        "tinyconfig": [
            "tools/include/linux/types.h",
            "tools/include/linux/kernel.h",
            "arch/x86/include/uapi/asm/stat.h",
        ]
    }
    return [Path(p) for p in missing_sources[config]]


if __name__ == "__main__":
    """
    cmd_graph_based_kernel_build.py <src_tree> <output_tree>
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

    cmd_src_tree = (src_tree.parent / f"{src_tree.name}_cmd").resolve()
    cmd_output_tree = (cmd_src_tree / os.path.relpath(output_tree, src_tree)).resolve()
    missing_sources_in_cmd_graph_path = (script_path / "missing_sources_in_cmd_graph.json").resolve()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # missing files that need to be added manually because corresponding error messages are difficult to parse:
    missing_sources_in_cmd_graph: list[Path] = _get_manual_missing_sources(config="tinyconfig")
    if (missing_sources_in_cmd_graph_path).exists():
        with open(missing_sources_in_cmd_graph_path, "r") as f:
            missing_sources_in_cmd_graph += [Path(p) for p in json.load(f)]

    if not cmd_src_tree.exists():
        _create_cmd_graph_based_kernel_directory(
            src_tree,
            output_tree,
            cmd_src_tree,
            cmd_output_tree,
            root_output_in_tree,
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
