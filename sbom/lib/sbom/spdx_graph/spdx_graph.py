# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from typing import Mapping
from sbom.cmd_graph import CmdGraph, iter_cmd_graph
from sbom.path_utils import PathStr
from sbom.spdx.build import Build
from sbom.spdx.core import (
    SoftwareAgent,
    SpdxObject,
    CreationInfo,
    Relationship,
    SpdxDocument,
)
from sbom.spdx.simplelicensing import LicenseExpression
from sbom.spdx.software import Package, File, Sbom
from sbom.spdx_graph.kernel_file import KernelFile, build_kernel_file_element


def build_spdx_graph(
    cmd_graph: CmdGraph,
    output_tree: PathStr,
    src_tree: PathStr,
    spdx_uri_prefix: str,
    package_name: str,
    package_license: str,
    build_version: str,
) -> list[SpdxObject]:
    spdx_document = SpdxDocument(
        profileConformance=["core", "software", "build", "simpleLicensing"],
    )
    agent = SoftwareAgent(name="KernelSbom")
    creation_info = CreationInfo(createdBy=[agent])
    sbom = Sbom(software_sbomType=["build"])

    # src and output tree elements
    src_tree_element = File(
        name="$(src_tree)",
        software_fileKind="directory",
    )
    output_tree_element = File(
        name="$(output_tree)",
        software_fileKind="directory",
    )
    src_tree_contains_relationship = Relationship(
        relationshipType="contains",
        from_=src_tree_element,
        to=[],
    )
    output_tree_contains_relationship = Relationship(
        relationshipType="contains",
        from_=output_tree_element,
        to=[],
    )

    # package elements
    package = Package(
        name=package_name,
        software_packageVersion=build_version,
        originatedBy=[agent],
    )
    package_license_expression = LicenseExpression(simplelicensing_licenseExpression=package_license)
    package_hasDeclaredLicense_relationship = Relationship(
        relationshipType="hasDeclaredLicense",
        from_=package,
        to=[package_license_expression],
    )
    package_contains_roots_relationship = Relationship(
        relationshipType="contains",
        from_=package,
        to=[],
    )

    # file elements
    files: dict[PathStr, KernelFile] = {
        node.absolute_path: build_kernel_file_element(node.absolute_path, output_tree, src_tree)
        for node in iter_cmd_graph(cmd_graph)
    }
    file_relationships = _build_file_relationships(cmd_graph, files, spdx_uri_prefix)
    file_license_identifiers = {
        file.license_identifier: LicenseExpression(simplelicensing_licenseExpression=file.license_identifier)
        for file in files.values()
        if file.license_identifier is not None
    }
    file_license_relationships = [
        Relationship(
            relationshipType="hasDeclaredLicense",
            from_=file,
            to=[file_license_identifiers[file.license_identifier]],
        )
        for file in files.values()
        if file.license_identifier is not None
    ]

    # update relationships
    spdx_document.rootElement = [sbom]

    sbom.rootElement = [package]
    sbom.element = [
        package,
        package_license_expression,
        package_hasDeclaredLicense_relationship,
        package_contains_roots_relationship,
        *files.values(),
        *file_relationships,
        *file_license_identifiers.values(),
        *file_license_relationships,
    ]

    root_paths = {node.absolute_path for node in cmd_graph.roots}
    package_contains_roots_relationship.to = [file for file in files.values() if file.absolute_path in root_paths]

    if src_tree != output_tree:
        sbom.element = [
            src_tree_element,
            src_tree_contains_relationship,
            output_tree_element,
            output_tree_contains_relationship,
            *sbom.element,
        ]
        src_tree_contains_relationship.to = [file for file in files.values() if file.tree == "src_tree"]
        output_tree_contains_relationship.to = [file for file in files.values() if file.tree == "output_tree"]

    return [
        spdx_document,
        agent,
        creation_info,
        sbom,
        *sbom.element,
    ]


def _build_file_relationships(
    cmd_graph: CmdGraph, file_elements: Mapping[PathStr, File], spdx_uri_prefix: str
) -> list[Build | Relationship]:
    # create a relationship between each node (output file) and its children (input files)
    build_and_relationship_elements: list[Build | Relationship] = []
    for node in iter_cmd_graph(cmd_graph):
        if len(node.children) == 0:
            continue
        build_element = Build(
            build_buildType=f"{spdx_uri_prefix}Kbuild",
            comment=node.cmd_file.savedcmd if node.cmd_file is not None else None,
        )
        hasInput_relationship = Relationship(
            relationshipType="hasInput",
            from_=build_element,
            to=[file_elements[child_node.absolute_path] for child_node in node.children],
        )
        hasOutput_relationship = Relationship(
            relationshipType="hasOutput",
            from_=build_element,
            to=[file_elements[node.absolute_path]],
        )
        build_and_relationship_elements += [build_element, hasInput_relationship, hasOutput_relationship]

    return build_and_relationship_elements
