# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
from enum import Enum
import logging
import os
from typing import Literal

from sbom.environment import Environment
from sbom.spdx.spdxId import SpdxIdGenerator
from typing import Mapping
from sbom.cmd_graph import CmdGraph, iter_cmd_graph
from sbom.path_utils import PathStr
from sbom.spdx.build import Build
from sbom.spdx.core import (
    Element,
    ExternalMap,
    NamespaceMap,
    SoftwareAgent,
    SpdxObject,
    CreationInfo,
    Relationship,
    SpdxDocument,
)
from sbom.spdx.simplelicensing import LicenseExpression
from sbom.spdx.software import Package, File, Sbom
from sbom.spdx_graph.kernel_file import KernelFile, KernelFileLocation, build_kernel_file_element


class KernelSbomKind(Enum):
    SOURCE = "source"
    BUILD = "build"
    OUTPUT = "output"


@dataclass
class SpdxIdGeneratorCollection:
    base: SpdxIdGenerator
    source: SpdxIdGenerator
    build: SpdxIdGenerator
    output: SpdxIdGenerator

    def get(self, generator_kind: KernelSbomKind | Literal["general"]) -> SpdxIdGenerator:
        generator_mapping: dict[KernelSbomKind | Literal["general"], SpdxIdGenerator] = {
            "general": self.base,
            KernelSbomKind.SOURCE: self.source,
            KernelSbomKind.BUILD: self.build,
            KernelSbomKind.OUTPUT: self.output,
        }
        return generator_mapping[generator_kind]


@dataclass
class SpdxGraphOptions:
    build_type: str
    package_names: dict[str, str]
    package_license: str
    package_version: str | None
    package_copyright_text: str | None


@dataclass
class SpdxGraph:
    spdx_document: SpdxDocument
    agent: SoftwareAgent
    creation_info: CreationInfo
    sbom: Sbom

    def to_list(self) -> list[SpdxObject]:
        return [
            self.spdx_document,
            self.agent,
            self.creation_info,
            self.sbom,
            *self.sbom.element,
        ]


def build_spdx_graphs(
    cmd_graph: CmdGraph,
    output_tree: PathStr,
    src_tree: PathStr,
    spdx_id_generators: SpdxIdGeneratorCollection,
    options: SpdxGraphOptions,
) -> dict[KernelSbomKind, list[SpdxObject]]:
    if src_tree == output_tree:
        logging.warning(
            "Skip creation of dedicated source sbom and add source files into the build sbom because source files cannot be reliably classified when src tree and output tree are equal. "
        )
        build_graph, output_graph = _create_build_and_output_spdx_graphs(
            cmd_graph,
            output_tree,
            src_tree,
            spdx_id_generators,
            options,
        )
        return {
            KernelSbomKind.BUILD: build_graph.to_list(),
            KernelSbomKind.OUTPUT: output_graph.to_list(),
        }
    source_graph, build_graph, output_graph = _create_source_build_and_output_spdx_graphs(
        cmd_graph,
        output_tree,
        src_tree,
        spdx_id_generators,
        options,
    )
    return {
        KernelSbomKind.SOURCE: source_graph.to_list(),
        KernelSbomKind.BUILD: build_graph.to_list(),
        KernelSbomKind.OUTPUT: output_graph.to_list(),
    }


def _create_build_and_output_spdx_graphs(
    cmd_graph: CmdGraph,
    output_tree: PathStr,
    src_tree: PathStr,
    spdx_id_generators: SpdxIdGeneratorCollection,
    options: SpdxGraphOptions,
) -> tuple[SpdxGraph, SpdxGraph]:
    # Create Shared spdx objects
    agent = SoftwareAgent(
        spdxId=spdx_id_generators.base.generate(),
        name="KernelSbom",
    )
    creation_info = CreationInfo(createdBy=[agent])

    # SpdxDocument elements
    _, build_spdx_document, output_spdx_document = _spdx_document_elements(spdx_id_generators)
    build_spdx_document.namespaceMap = [
        nm for nm in build_spdx_document.namespaceMap if nm.namespace != spdx_id_generators.source.namespace
    ]

    # Sbom elements
    build_sbom = Sbom(
        spdxId=spdx_id_generators.build.generate(),
        software_sbomType=["build"],
    )
    output_sbom = Sbom(
        spdxId=spdx_id_generators.output.generate(),
        software_sbomType=["build"],
    )

    # File elements
    file_element_map: dict[PathStr, KernelFile] = {
        node.absolute_path: build_kernel_file_element(
            node.absolute_path, output_tree, src_tree, spdx_id_generators.build, spdx_id_generators.build
        )
        for node in iter_cmd_graph(cmd_graph)
    }
    root_file_elements: list[File] = [file_element_map[node.absolute_path] for node in cmd_graph.roots]
    file_relationships = _file_relationships(cmd_graph, file_element_map, options.build_type, spdx_id_generators.build)

    # Source file license elements
    source_file_license_identifiers, source_file_license_relationships = _source_file_license_elements(
        [*file_element_map.values()], spdx_id_generators.build
    )

    # Output package element
    (
        output_package_elements,
        output_package_contains_roots_relationships,
        output_package_hasDeclaredLicense_relationships,
        output_package_license_expression,
    ) = _output_package_elements(
        root_file_elements,
        options.package_names,
        options.package_license,
        options.package_version,
        options.package_copyright_text,
        agent,
        spdx_id_generators.output,
    )

    # ExternalMap elements
    output_imports = [ExternalMap(externalSpdxId=file.spdxId) for file in root_file_elements]

    # Update relationships
    build_spdx_document.rootElement = [build_sbom]
    output_spdx_document.rootElement = [output_sbom]

    output_spdx_document.import_ = output_imports

    build_sbom.rootElement = [*root_file_elements]
    build_sbom.element = [
        *file_element_map.values(),
        *source_file_license_identifiers,
        *source_file_license_relationships,
        *file_relationships,
    ]
    output_sbom.rootElement = [*output_package_elements]
    output_sbom.element = [
        *output_package_elements,
        *output_package_contains_roots_relationships,
        *output_package_hasDeclaredLicense_relationships,
        output_package_license_expression,
        *root_file_elements,
    ]

    build_graph = SpdxGraph(build_spdx_document, agent, creation_info, build_sbom)
    output_graph = SpdxGraph(output_spdx_document, agent, creation_info, output_sbom)
    return build_graph, output_graph


def _create_source_build_and_output_spdx_graphs(
    cmd_graph: CmdGraph,
    output_tree: PathStr,
    src_tree: PathStr,
    spdx_id_generators: SpdxIdGeneratorCollection,
    options: SpdxGraphOptions,
) -> tuple[SpdxGraph, SpdxGraph, SpdxGraph]:
    # Create Shared spdx objects
    agent = SoftwareAgent(
        spdxId=spdx_id_generators.base.generate(),
        name="KernelSbom",
    )
    creation_info = CreationInfo(createdBy=[agent])

    # Spdx Document and Sbom
    source_spdx_document, build_spdx_document, output_spdx_document = _spdx_document_elements(spdx_id_generators)
    source_sbom, build_sbom, output_sbom = _sbom_elements(spdx_id_generators)

    # Src and output tree elements
    src_tree_element = File(
        spdxId=spdx_id_generators.source.generate(),
        name="$(src_tree)",
        software_fileKind="directory",
    )
    output_tree_element = File(
        spdxId=spdx_id_generators.build.generate(),
        name="$(output_tree)",
        software_fileKind="directory",
    )
    src_tree_contains_relationship = Relationship(
        spdxId=spdx_id_generators.source.generate(),
        relationshipType="contains",
        from_=src_tree_element,
        to=[],
    )
    output_tree_contains_relationship = Relationship(
        spdxId=spdx_id_generators.build.generate(),
        relationshipType="contains",
        from_=output_tree_element,
        to=[],
    )

    # File elements
    file_element_map: dict[PathStr, KernelFile] = {
        node.absolute_path: build_kernel_file_element(
            node.absolute_path, output_tree, src_tree, spdx_id_generators.source, spdx_id_generators.build
        )
        for node in iter_cmd_graph(cmd_graph)
    }
    source_file_elements: list[Element] = []
    output_file_elements: list[Element] = []
    for file_element in file_element_map.values():
        if file_element.file_location == KernelFileLocation.SOURCE_TREE:
            source_file_elements.append(file_element)
        else:
            output_file_elements.append(file_element)
    root_file_elements: list[File] = [file_element_map[node.absolute_path] for node in cmd_graph.roots]
    file_relationships = _file_relationships(cmd_graph, file_element_map, options.build_type, spdx_id_generators.build)

    # Source file license elements
    source_file_license_identifiers, source_file_license_relationships = _source_file_license_elements(
        [*file_element_map.values()], spdx_id_generators.source
    )

    # Output package elements
    (
        output_package_elements,
        output_package_contains_roots_relationships,
        output_package_hasDeclaredLicense_relationships,
        output_package_license_expression,
    ) = _output_package_elements(
        root_file_elements,
        options.package_names,
        options.package_license,
        options.package_version,
        options.package_copyright_text,
        agent,
        spdx_id_generators.output,
    )

    # External Maps
    build_imports = [ExternalMap(externalSpdxId=file_element.spdxId) for file_element in source_file_elements]
    output_imports = [ExternalMap(externalSpdxId=file_element.spdxId) for file_element in root_file_elements]

    # Update relationships
    source_spdx_document.rootElement = [source_sbom]
    build_spdx_document.rootElement = [build_sbom]
    output_spdx_document.rootElement = [output_sbom]

    build_spdx_document.import_ = build_imports
    output_spdx_document.import_ = output_imports

    source_sbom.rootElement = [src_tree_element]
    source_sbom.element = [
        src_tree_element,
        src_tree_contains_relationship,
        *source_file_elements,
        *source_file_license_identifiers,
        *source_file_license_relationships,
    ]
    build_sbom.rootElement = [output_tree_element]
    build_sbom.element = [
        output_tree_element,
        output_tree_contains_relationship,
        *output_file_elements,
        *file_relationships,
    ]
    output_sbom.rootElement = [*output_package_elements]
    output_sbom.element = [
        *output_package_elements,
        *output_package_contains_roots_relationships,
        *output_package_hasDeclaredLicense_relationships,
        output_package_license_expression,
        *root_file_elements,
    ]

    src_tree_contains_relationship.to = source_file_elements
    output_tree_contains_relationship.to = output_file_elements

    # create Spdx graphs
    source_graph = SpdxGraph(source_spdx_document, agent, creation_info, source_sbom)
    build_graph = SpdxGraph(build_spdx_document, agent, creation_info, build_sbom)
    output_graph = SpdxGraph(output_spdx_document, agent, creation_info, output_sbom)

    return source_graph, build_graph, output_graph


def _spdx_document_elements(
    spdx_id_generators: SpdxIdGeneratorCollection,
) -> tuple[SpdxDocument, SpdxDocument, SpdxDocument]:
    source_spdx_document = SpdxDocument(
        spdxId=spdx_id_generators.source.generate(),
        profileConformance=["core", "software", "simpleLicensing"],
        namespaceMap=[
            NamespaceMap(prefix=generator.prefix, namespace=generator.namespace)
            for generator in [spdx_id_generators.source, spdx_id_generators.base]
            if generator.prefix is not None
        ],
    )
    build_spdx_document = SpdxDocument(
        spdxId=spdx_id_generators.build.generate(),
        profileConformance=["core", "software", "build"],
        namespaceMap=[
            NamespaceMap(prefix=generator.prefix, namespace=generator.namespace)
            for generator in [spdx_id_generators.build, spdx_id_generators.source, spdx_id_generators.base]
            if generator.prefix is not None
        ],
    )
    output_spdx_document = SpdxDocument(
        spdxId=spdx_id_generators.output.generate(),
        profileConformance=["core", "software", "build", "simpleLicensing"],
        namespaceMap=[
            NamespaceMap(prefix=generator.prefix, namespace=generator.namespace)
            for generator in [spdx_id_generators.output, spdx_id_generators.build, spdx_id_generators.base]
            if generator.prefix is not None
        ],
    )
    return source_spdx_document, build_spdx_document, output_spdx_document


def _sbom_elements(spdx_id_generators: SpdxIdGeneratorCollection) -> tuple[Sbom, Sbom, Sbom]:
    source_sbom = Sbom(
        spdxId=spdx_id_generators.source.generate(),
        software_sbomType=["source"],
    )
    build_sbom = Sbom(
        spdxId=spdx_id_generators.build.generate(),
        software_sbomType=["build"],
    )
    output_sbom = Sbom(
        spdxId=spdx_id_generators.output.generate(),
        software_sbomType=["build"],
    )
    return source_sbom, build_sbom, output_sbom


def _source_file_license_elements(
    files: list[KernelFile], spdx_id_generator: SpdxIdGenerator
) -> tuple[list[LicenseExpression], list[Relationship]]:
    source_file_license_identifiers = {
        file.license_identifier: LicenseExpression(
            spdxId=spdx_id_generator.generate(),
            simplelicensing_licenseExpression=file.license_identifier,
        )
        for file in files
        if file.license_identifier is not None
    }
    source_file_license_relationships = [
        Relationship(
            spdxId=spdx_id_generator.generate(),
            relationshipType="hasDeclaredLicense",
            from_=file,
            to=[source_file_license_identifiers[file.license_identifier]],
        )
        for file in files
        if file.license_identifier is not None
    ]
    return ([*source_file_license_identifiers.values()], source_file_license_relationships)


def _output_package_elements(
    root_file_elements: list[File],
    package_names: dict[str, str],
    package_license: str,
    package_version: str | None,
    package_copyright_text: str | None,
    agent: SoftwareAgent,
    output_id_generator: SpdxIdGenerator,
) -> tuple[list[Package], list[Relationship], list[Relationship], LicenseExpression]:
    package_elements = [
        Package(
            spdxId=output_id_generator.generate(),
            name=package_names[filename] if (filename := os.path.basename(file.name)) in package_names else filename,
            software_packageVersion=package_version,
            software_copyrightText=package_copyright_text,
            originatedBy=[agent],
            comment=f"Architecture={arch}" if (arch := Environment.ARCH or Environment.SRCARCH) else None,
            software_primaryPurpose=file.software_primaryPurpose,
        )
        for file in root_file_elements
    ]
    package_contains_file_relationships = [
        Relationship(
            spdxId=output_id_generator.generate(),
            relationshipType="contains",
            from_=package,
            to=[file],
        )
        for package, file in zip(package_elements, root_file_elements)
    ]
    package_license_expression = LicenseExpression(
        spdxId=output_id_generator.generate(),
        simplelicensing_licenseExpression=package_license,
    )
    package_hasDeclaredLicense_relationships = [
        Relationship(
            spdxId=output_id_generator.generate(),
            relationshipType="hasDeclaredLicense",
            from_=package,
            to=[package_license_expression],
        )
        for package in package_elements
    ]
    return (
        package_elements,
        package_contains_file_relationships,
        package_hasDeclaredLicense_relationships,
        package_license_expression,
    )


def _file_relationships(
    cmd_graph: CmdGraph,
    file_elements: Mapping[PathStr, File],
    build_type: str,
    build_id_generator: SpdxIdGenerator,
) -> list[Build | Relationship]:
    # Create a relationship between each node (output file) and its children (input files)
    build_and_relationship_elements: list[Build | Relationship] = []
    for node in iter_cmd_graph(cmd_graph):
        if len(node.children) == 0:
            continue
        build_element = Build(
            spdxId=build_id_generator.generate(),
            build_buildType=build_type,
            comment=node.cmd_file.savedcmd if node.cmd_file is not None else None,
        )
        hasInput_relationship = Relationship(
            spdxId=build_id_generator.generate(),
            relationshipType="hasInput",
            from_=build_element,
            to=[file_elements[child_node.absolute_path] for child_node in node.children],
        )
        hasOutput_relationship = Relationship(
            spdxId=build_id_generator.generate(),
            relationshipType="hasOutput",
            from_=build_element,
            to=[file_elements[node.absolute_path]],
        )
        build_and_relationship_elements += [build_element, hasInput_relationship, hasOutput_relationship]

    return build_and_relationship_elements
