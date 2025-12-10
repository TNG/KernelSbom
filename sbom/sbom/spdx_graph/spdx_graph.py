# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from datetime import datetime
from typing import Protocol

import sbom.sbom_logging as sbom_logging
from sbom.config import KernelSpdxDocumentKind
from sbom.cmd_graph import CmdGraph
from sbom.path_utils import PathStr
from sbom.spdx.core import SpdxObject
from sbom.spdx_graph.expand_spdxIds_for_non_expandable_properties import expand_spdxIds_for_non_expandable_properties
from sbom.spdx_graph.kernel_file import KernelFileCollection
from sbom.spdx_graph.spdx_graph_model import SpdxGraph, SpdxIdGeneratorCollection
from sbom.spdx_graph.shared_spdx_elements import SharedSpdxElements
from sbom.spdx_graph.spdx_source_graph import SpdxSourceGraph
from sbom.spdx_graph.spdx_build_graph import SpdxBuildGraph
from sbom.spdx_graph.spdx_output_graph import SpdxOutputGraph


class SpdxGraphConfig(Protocol):
    obj_tree: PathStr
    src_tree: PathStr
    created: datetime
    build_type: str
    build_id: str | None
    package_license: str
    package_version: str | None
    package_copyright_text: str | None


def build_spdx_graphs(
    cmd_graph: CmdGraph,
    spdx_id_generators: SpdxIdGeneratorCollection,
    config: SpdxGraphConfig,
) -> dict[KernelSpdxDocumentKind, list[SpdxObject]]:
    shared_elements = SharedSpdxElements.create(spdx_id_generators.base, config.created)
    kernel_files = KernelFileCollection.create(cmd_graph, config.obj_tree, config.src_tree, spdx_id_generators)
    output_graph = SpdxOutputGraph.create(
        root_files=list(kernel_files.output.values()),
        shared_elements=shared_elements,
        spdx_id_generators=spdx_id_generators,
        config=config,
    )
    spdx_graphs = {
        KernelSpdxDocumentKind.OUTPUT: output_graph.to_list(),
    }

    source_graph: SpdxGraph | None = None
    if len(kernel_files.source) > 0:
        source_graph = SpdxSourceGraph.create(
            source_files=list(kernel_files.source.values()),
            shared_elements=shared_elements,
            spdx_id_generators=spdx_id_generators,
        )
        spdx_graphs[KernelSpdxDocumentKind.SOURCE] = source_graph.to_list()
    else:
        sbom_logging.warning(
            "Skipped creating a dedicated source SBOM because source files cannot be reliably classified when the source and object trees are identical. Added source files to the build SBOM instead."
        )

    build_graph = SpdxBuildGraph.create(
        cmd_graph,
        kernel_files,
        shared_elements,
        output_graph.high_level_build_element,
        spdx_id_generators,
        config,
    )
    spdx_graphs[KernelSpdxDocumentKind.BUILD] = build_graph.to_list()

    return {
        k: expand_spdxIds_for_non_expandable_properties(spdx_graph, spdx_id_generators)
        for k, spdx_graph in spdx_graphs.items()
    }
