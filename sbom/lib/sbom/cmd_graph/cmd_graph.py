# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from itertools import chain
from dataclasses import dataclass, field
from typing import Iterator

from sbom.cmd_graph.cmd_graph_node import CmdGraphNode, CmdGraphNodeConfig
from sbom.path_utils import PathStr


@dataclass
class CmdGraph:
    roots: list[CmdGraphNode] = field(default_factory=list[CmdGraphNode])

    @classmethod
    def create(cls, root_paths: list[PathStr], config: CmdGraphNodeConfig) -> "CmdGraph":
        node_cache: dict[PathStr, CmdGraphNode] = {}
        root_nodes = [CmdGraphNode.create(root_path, config, node_cache) for root_path in root_paths]
        return CmdGraph(root_nodes)

    def __iter__(self) -> Iterator[CmdGraphNode]:
        visited: set[PathStr] = set()
        node_stack: list[CmdGraphNode] = self.roots.copy()
        while len(node_stack) > 0:
            node = node_stack.pop(0)
            if node.absolute_path in visited:
                continue

            visited.add(node.absolute_path)
            node_stack = list(chain(node.children, node_stack))
            yield node
