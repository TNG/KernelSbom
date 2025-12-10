# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


import logging
import os
import pickle

from sbom.cmd_graph import CmdGraph
from sbom.cmd_graph.cmd_graph_node import CmdGraphNodeConfig
from sbom.path_utils import PathStr


def save_cmd_graph(node: CmdGraph, path: PathStr) -> None:
    with open(path, "wb") as f:
        pickle.dump(node, f)


def load_cmd_graph(path: PathStr) -> CmdGraph:
    with open(path, "rb") as f:
        return pickle.load(f)


def build_or_load_cmd_graph(
    target_paths: list[PathStr], cmd_graph_path: PathStr, config: CmdGraphNodeConfig
) -> CmdGraph:
    if os.path.exists(cmd_graph_path):
        logging.debug("Load cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
    else:
        logging.debug("Build cmd graph")
        cmd_graph = CmdGraph.create(target_paths, config)
        save_cmd_graph(cmd_graph, cmd_graph_path)
    return cmd_graph
