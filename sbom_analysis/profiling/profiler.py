#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import cProfile
import os
import pstats
import sys

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd_graph.cmd_graph import build_cmd_graph  # noqa: E402


root_paths = ["arch/x86/boot/bzImage"]
src_tree = "../linux"
output_tree = "../linux/kernel_build"
os.environ["SRCARCH"] = "x86"

profiler = cProfile.Profile()
profiler.enable()

# Actual function call
cmd_graph = build_cmd_graph(root_paths, output_tree, src_tree)

profiler.disable()

# Print stats
stats = pstats.Stats(profiler)
stats.sort_stats("cumulative").print_stats(20)
