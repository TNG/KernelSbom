# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from pathlib import Path
from sbom.cmd.cmd_graph import CmdGraph, iter_cmd_graph
from sbom.spdx.core import (
    SoftwareAgent,
    SpdxEntity,
    CreationInfo,
    Hash,
    Relationship,
    SpdxDocument,
)
from sbom.spdx.simplelicensing import LicenseExpression
from sbom.spdx.software import Package, File, Sbom
import hashlib
import os
import sbom.errors as sbom_errors
import logging

from sbom.spdx.spdxId import generate_spdx_id


def build_spdx_graph(
    cmd_graph: CmdGraph,
    output_tree: Path,
    src_tree: Path,
    buildVersion: str = "NOASSERTION",
    package_name: str = "Linux Kernel",
) -> list[SpdxEntity]:
    agent = SoftwareAgent(name="KernelSbom")
    creation_info = CreationInfo(createdBy=[agent])
    package = Package(
        name=package_name,
        software_packageVersion=buildVersion,
        originatedBy=[agent],
        software_copyrightText="NOASSERTION",
    )
    package_license = LicenseExpression(
        simplelicensing_licenseExpression="GPL-2.0 WITH Linux-syscall-note"  # based on https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/COPYING
    )
    package_hasDeclaredLicense_relationship = Relationship(
        relationshipType="hasDeclaredLicense",
        from_=package,
        to=[package_license],
    )
    sbom = Sbom(
        software_sbomType=["build"],
        rootElement=[package],
    )
    spdx_document = SpdxDocument(
        profileConformance=["core", "software"],
        rootElement=[sbom],
    )
    file_elements, file_relationship_elements = _build_file_graph(cmd_graph, output_tree, src_tree)

    # update direct parent-child relations
    sbom.element = [package, *file_elements]
    spdx_document.element = [sbom, *sbom.element]

    return [
        agent,
        creation_info,
        package,
        package_hasDeclaredLicense_relationship,
        sbom,
        spdx_document,
        *file_elements,
        *file_relationship_elements,
    ]


def _build_file_graph(cmd_graph: CmdGraph, output_tree: Path, src_tree: Path) -> tuple[list[File], list[Relationship]]:
    # First cmd graph traversal: create a file element for each node
    file_elements: dict[Path, File] = {
        node.absolute_path: _build_file_element(node.absolute_path, src_tree, output_tree)
        for node in iter_cmd_graph(cmd_graph)
    }

    # Second cmd graph traversal: create a relationship for each (child)node representing the generation of all its parents
    relationhip_elements: dict[Path, Relationship] = {}
    for node in iter_cmd_graph(cmd_graph):
        output_file_element = file_elements[node.absolute_path]
        for child_node in node.children:
            if child_node.absolute_path in relationhip_elements:
                relationhip_elements[child_node.absolute_path].to.append(output_file_element)
                continue
            input_file_element = file_elements[child_node.absolute_path]
            relationhip_elements[child_node.absolute_path] = Relationship(
                relationshipType="generates",
                from_=input_file_element,
                to=[output_file_element],
            )

    return list(file_elements.values()), list(relationhip_elements.values())


def _build_file_element(absolute_path: Path, output_tree: Path, src_tree: Path) -> File:
    is_in_output_tree = absolute_path.is_relative_to(output_tree)
    is_in_src_tree = absolute_path.is_relative_to(src_tree)

    # file element name should be relative to output or src tree if possible
    if is_in_output_tree:
        file_element_name = os.path.relpath(absolute_path, output_tree)
    elif is_in_src_tree:
        file_element_name = os.path.relpath(absolute_path, src_tree)
    else:
        file_element_name = str(absolute_path)

    # Create file hash if possible. Hashes for files outside the src and output trees are optional.
    verifiedUsing: list[Hash] = []
    if absolute_path.exists():
        verifiedUsing = [Hash(algorithm="sha256", hashValue=_sha256(absolute_path))]
    elif is_in_output_tree or is_in_src_tree:
        sbom_errors.log(f"Cannot compute hash for {absolute_path} because file does not exist.")
    else:
        logging.warning(f"Cannot compute hash for {absolute_path} because file does not exist.")

    file_element = File(
        spdxId=generate_spdx_id("software_File", file_element_name),
        name=file_element_name,
        software_copyrightText="NOASSERTION",
        verifiedUsing=verifiedUsing,
    )

    return file_element


def _sha256(path: Path) -> str:
    """Compute the SHA-256 hash of a file."""
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()
