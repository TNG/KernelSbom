# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from pathlib import Path
from sbom.cmd.cmd_graph import CmdGraph, CmdGraphNode
from sbom.spdx.core import (
    SoftwareAgent,
    SpdxEntity,
    CreationInfo,
    Hash,
    Relationship,
    SpdxDocument,
)
from sbom.spdx.software import Package, File, Sbom
import hashlib


def build_spdx_graph(cmd_graph: CmdGraph, buildVersion: str, package_name: str = "Linux Kernel") -> list[SpdxEntity]:
    agent = SoftwareAgent(name="KernelSbom")
    creation_info = CreationInfo(createdBy=[agent])
    software_package = Package(
        name=package_name,
        software_packageVersion=buildVersion,
        originatedBy=[agent],
        software_copyrightText="NOASSERTION",
    )
    software_sbom = Sbom(
        software_sbomType=["build"],
        rootElement=[software_package],
    )
    spdx_document = SpdxDocument(
        profileConformance=["core", "software", "build"],
        rootElement=[software_sbom],
    )
    file_graph = _build_file_graph(cmd_graph)
    return [
        agent,
        creation_info,
        software_package,
        software_sbom,
        spdx_document,
        *file_graph,
    ]


def _build_file_graph(node: CmdGraphNode | CmdGraph) -> list[SpdxEntity]:
    if isinstance(node, CmdGraph):
        return [spdx_entity for root_node in node.roots for spdx_entity in _build_file_graph(root_node)]

    file_graph: list[SpdxEntity] = []
    for child in node.children:
        file_graph.extend(_build_file_graph(child))

    file_element = File(
        name=str(node.absolute_path),
        software_copyrightText="NOASSERTION",
        verifiedUsing=[Hash(hashValue=_sha256(node.absolute_path))],
    )

    return file_graph + [file_element]


def _sha256(path: Path) -> str:
    """Compute the SHA-256 hash of a file."""
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()
