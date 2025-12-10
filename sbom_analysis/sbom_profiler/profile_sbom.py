#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

# ruff: noqa: E402

import cProfile
from dataclasses import dataclass
from datetime import datetime
import os
import sys
import pstats
from typing import Callable

from sbom.spdx_graph import build_spdx_graphs


# Add the sbom package to the sys.path
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, "../../sbom/lib"))

# Imports from the sbom package
from sbom.path_utils import PathStr
from sbom.spdx import SpdxIdGenerator
from sbom.cmd_graph import build_cmd_graph
from sbom.spdx_graph.spdx_graph_model import SpdxIdGeneratorCollection
# from sbom.cmd_graph import CmdGraph, build_cmd_graph
# from sbom.spdx_graph import SpdxIdGeneratorCollection, build_spdx_graphs


@dataclass
class ProfilerConfig:
    obj_tree: PathStr
    src_tree: PathStr
    fail_on_unknown_build_command: bool = True
    created: datetime = datetime.now()
    build_type: str = "kernel"
    build_id: str | None = None
    package_license: str = "GPL-2.0-only"
    package_version: str | None = None
    package_copyright_text: str | None = None


from typing import TypeVar

T = TypeVar("T")


def _profile_function(func: Callable[[], T]) -> T:
    profiler = cProfile.Profile()
    profiler.enable()
    result = func()
    profiler.disable()
    stats = pstats.Stats(profiler)
    stats.sort_stats("cumulative")
    stats.print_stats(15)
    return result


if __name__ == "__main__":
    script_path = os.path.dirname(__file__)
    src_tree = (
        os.path.realpath(sys.argv[1])
        if len(sys.argv) >= 2 and sys.argv[1]
        else os.path.realpath(os.path.join(script_path, "../../../linux"))
    )
    obj_tree = (
        os.path.realpath(sys.argv[2]) if len(sys.argv) >= 3 and sys.argv[2] else os.path.join(src_tree, "kernel_build")
    )
    config = ProfilerConfig(obj_tree, src_tree)
    # spdx_id_generators = SpdxIdGeneratorCollection(
    #     base=SpdxIdGenerator(namespace="base", prefix="b"),
    #     source=SpdxIdGenerator(namespace="source", prefix="s"),
    #     build=SpdxIdGenerator(namespace="build", prefix="b"),
    #     output=SpdxIdGenerator(namespace="output", prefix="o"),
    # )

    # cmd_graph = _profile_function(func=lambda: CmdGraph.create(root_paths=["arch/x86/boot/bzImage"], config=config))
    # _profile_function(func=lambda: build_spdx_graphs(cmd_graph, spdx_id_generators, config))

    spdx_id_generators = SpdxIdGeneratorCollection(
        base=SpdxIdGenerator(namespace="base", prefix="b"),
        source=SpdxIdGenerator(namespace="source", prefix="s"),
        build=SpdxIdGenerator(namespace="build", prefix="b"),
        output=SpdxIdGenerator(namespace="output", prefix="o"),
    )

    cmd_graph = _profile_function(func=lambda: build_cmd_graph(root_paths=["arch/x86/boot/bzImage"], config=config))
    _profile_function(func=lambda: build_spdx_graphs(cmd_graph, spdx_id_generators, config))
