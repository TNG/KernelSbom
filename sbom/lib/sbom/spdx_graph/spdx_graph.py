# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from sbom.cmd_graph.cmd_graph import CmdGraph, iter_cmd_graph
from sbom.path_utils import PathStr
from sbom.spdx.build import Build
from sbom.spdx.core import (
    Element,
    SoftwareAgent,
    SpdxObject,
    CreationInfo,
    Relationship,
    SpdxDocument,
)
from sbom.spdx.simplelicensing import LicenseExpression
from sbom.spdx.software import Package, File, Sbom
from sbom.spdx.spdxId import generate_spdx_id
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
    spdx_document = SpdxDocument(profileConformance=["core", "software", "build", "simpleLicensing"])
    agent = SoftwareAgent(name="KernelSbom")
    creation_info = CreationInfo(createdBy=[agent])
    sbom = Sbom(software_sbomType=["build"])

    # src and output tree elements
    src_tree_element = File(
        spdxId=generate_spdx_id("software_File", "$(src_tree)"),
        name="$(src_tree)",
        software_fileKind="directory",
    )
    output_tree_element = File(
        spdxId=generate_spdx_id("software_File", "$(output_tree)"),
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
    src_and_output_tree_elements: list[Element] = (
        [
            src_tree_element,
            src_tree_contains_relationship,
            output_tree_element,
            output_tree_contains_relationship,
        ]
        if src_tree != output_tree
        else []
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

    file_elements, build_and_relationship_elements = _build_kernel_file_graph(
        cmd_graph, output_tree, src_tree, spdx_uri_prefix
    )

    # update relationships
    spdx_document.rootElement = [sbom]

    sbom.rootElement = [package]
    sbom.element = [
        *src_and_output_tree_elements,
        package,
        package_license_expression,
        package_hasDeclaredLicense_relationship,
        package_contains_roots_relationship,
        *file_elements,
        *build_and_relationship_elements,
    ]

    src_tree_contains_relationship.to = [file for file in file_elements if file.tree == "src_tree"]
    output_tree_contains_relationship.to = [file for file in file_elements if file.tree == "output_tree"]

    root_paths = {node.absolute_path for node in cmd_graph.roots}
    package_contains_roots_relationship.to = [file for file in file_elements if file.absolute_path in root_paths]

    return [
        spdx_document,
        agent,
        creation_info,
        sbom,
        *sbom.element,
    ]


def _build_kernel_file_graph(
    cmd_graph: CmdGraph,
    output_tree: PathStr,
    src_tree: PathStr,
    spdx_uri_prefix: str,
) -> tuple[list[KernelFile], list[Build | Relationship]]:
    # First cmd graph traversal: create a file element for each node
    file_elements: dict[PathStr, KernelFile] = {
        node.absolute_path: build_kernel_file_element(node.absolute_path, output_tree, src_tree)
        for node in iter_cmd_graph(cmd_graph)
    }

    # Second cmd graph traversal: create a relationship for each (child)node representing the generation of all its parents
    build_and_relationship_elements: list[Build | Relationship] = []
    for node in iter_cmd_graph(cmd_graph):
        if len(node.children) == 0:
            continue
        output_filename = file_elements[node.absolute_path].name
        build_element = Build(
            spdxId=generate_spdx_id("build_Build", f"{output_filename}"),
            build_buildType=f"{spdx_uri_prefix}Kbuild",
            comment=node.cmd_file.savedcmd if node.cmd_file is not None else None,
        )
        hasInput_relationship = Relationship(
            spdxId=generate_spdx_id("Relationship_hasInput", f"{output_filename}"),
            relationshipType="hasInput",
            from_=build_element,
            to=[file_elements[child_node.absolute_path] for child_node in node.children],
        )
        hasOutput_relationship = Relationship(
            spdxId=generate_spdx_id("Relationship_hasOutput", f"{output_filename}"),
            relationshipType="hasOutput",
            from_=build_element,
            to=[file_elements[node.absolute_path]],
        )
        build_and_relationship_elements += [build_element, hasInput_relationship, hasOutput_relationship]

    return list(file_elements.values()), build_and_relationship_elements
