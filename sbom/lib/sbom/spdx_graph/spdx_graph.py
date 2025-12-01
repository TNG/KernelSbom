# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from datetime import datetime
import logging
import os
from typing import Protocol

from sbom.config import KernelSpdxDocumentKind
from sbom.environment import Environment
from sbom.spdx.spdxId import SpdxIdGenerator
from typing import Mapping
from sbom.cmd_graph import CmdGraph, iter_cmd_graph
from sbom.path_utils import PathStr
from sbom.spdx.build import Build
from sbom.spdx.core import (
    DictionaryEntry,
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
from sbom.spdx.software import File, Sbom
from sbom.spdx_graph.kernel_file import KernelFile, KernelFileLocation, build_kernel_file_element
from sbom.spdx_graph.spdx_graph_model import SpdxBuildGraph, SpdxGraph, SpdxIdGeneratorCollection
from sbom.spdx_graph.spdx_output_graph import create_spdx_output_graph


class SpdxGraphConfig(Protocol):
    output_tree: PathStr
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
    if config.src_tree == config.output_tree:
        logging.warning(
            "Skip creation of dedicated source sbom and add source files into the build sbom because source files cannot be reliably classified when src tree and output tree are equal."
        )
        build_graph = _create_spdx_build_graph(cmd_graph, spdx_id_generators, config)
        output_graph = create_spdx_output_graph(build_graph, spdx_id_generators, config)
        return {
            KernelSpdxDocumentKind.BUILD: build_graph.to_list(),
            KernelSpdxDocumentKind.OUTPUT: output_graph.to_list(),
        }

    source_graph, build_graph = _create_spdx_source_and_build_graphs(cmd_graph, spdx_id_generators, config)
    output_graph = create_spdx_output_graph(build_graph, spdx_id_generators, config)
    return {
        KernelSpdxDocumentKind.SOURCE: source_graph.to_list(),
        KernelSpdxDocumentKind.BUILD: build_graph.to_list(),
        KernelSpdxDocumentKind.OUTPUT: output_graph.to_list(),
    }


def _create_spdx_build_graph(
    cmd_graph: CmdGraph,
    spdx_id_generators: SpdxIdGeneratorCollection,
    config: SpdxGraphConfig,
) -> SpdxBuildGraph:
    # Create shared SPDX objects
    agent, creation_info = _shared_elements(spdx_id_generators.base, config.created)

    # SpdxDocument elements
    _, build_spdx_document = _spdx_document_elements(spdx_id_generators)
    build_spdx_document.namespaceMap = [
        nm for nm in build_spdx_document.namespaceMap if nm.namespace != spdx_id_generators.source.namespace
    ]

    # Sbom element
    build_sbom = Sbom(
        spdxId=spdx_id_generators.build.generate(),
        software_sbomType=["build"],
    )

    # High-level build element
    config_source_element = _config_source_element(config.output_tree, config.src_tree, spdx_id_generators.build)
    high_level_build_element, high_level_build_ancestorOf_relationship = _high_level_build_elements(
        config.build_type, config.build_id, config_source_element, spdx_id_generators.build
    )

    # File elements
    file_element_map: dict[PathStr, KernelFile] = {
        node.absolute_path: build_kernel_file_element(
            node.absolute_path, config.output_tree, config.src_tree, spdx_id_generators.build, spdx_id_generators.build
        )
        for node in iter_cmd_graph(cmd_graph)
    }
    root_file_elements: list[File] = [file_element_map[node.absolute_path] for node in cmd_graph.roots]
    file_relationships = _file_relationships(
        cmd_graph, file_element_map, config.build_type, high_level_build_element.build_buildId, spdx_id_generators.build
    )

    # Source file license elements
    source_file_license_identifiers, source_file_license_relationships = _source_file_license_elements(
        [*file_element_map.values()], spdx_id_generators.build
    )

    # Update relationships
    build_spdx_document.rootElement = [build_sbom]

    build_sbom.rootElement = [*root_file_elements]
    build_sbom.element = [
        high_level_build_element,
        high_level_build_ancestorOf_relationship,
        config_source_element,
        *file_element_map.values(),
        *source_file_license_identifiers,
        *source_file_license_relationships,
        *file_relationships,
    ]

    high_level_build_ancestorOf_relationship.to = [
        element for element in file_relationships if isinstance(element, Build)
    ]

    build_graph = SpdxBuildGraph(
        build_spdx_document, agent, creation_info, build_sbom, root_file_elements, high_level_build_element
    )
    return build_graph


def _create_spdx_source_and_build_graphs(
    cmd_graph: CmdGraph,
    spdx_id_generators: SpdxIdGeneratorCollection,
    config: SpdxGraphConfig,
) -> tuple[SpdxGraph, SpdxBuildGraph]:
    # Create shared SPDX objects
    agent, creation_info = _shared_elements(spdx_id_generators.base, config.created)

    # Spdx Document and Sbom
    source_spdx_document, build_spdx_document = _spdx_document_elements(spdx_id_generators)
    source_sbom, build_sbom = _sbom_elements(spdx_id_generators)

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

    # High-level build element
    config_source_element = _config_source_element(config.output_tree, config.src_tree, spdx_id_generators.build)
    high_level_build_element, high_level_build_ancestorOf_relationship = _high_level_build_elements(
        config.build_type, config.build_id, config_source_element, spdx_id_generators.build
    )

    # File elements
    file_element_map: dict[PathStr, KernelFile] = {
        node.absolute_path: build_kernel_file_element(
            node.absolute_path, config.output_tree, config.src_tree, spdx_id_generators.source, spdx_id_generators.build
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
    file_relationships = _file_relationships(
        cmd_graph, file_element_map, config.build_type, high_level_build_element.build_buildId, spdx_id_generators.build
    )

    # Source file license elements
    source_file_license_identifiers, source_file_license_relationships = _source_file_license_elements(
        [*file_element_map.values()], spdx_id_generators.source
    )

    # External Maps
    build_imports = [ExternalMap(externalSpdxId=file_element.spdxId) for file_element in source_file_elements]

    # Update relationships
    source_spdx_document.rootElement = [source_sbom]
    build_spdx_document.rootElement = [build_sbom]

    build_spdx_document.import_ = build_imports

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
        high_level_build_element,
        high_level_build_ancestorOf_relationship,
        output_tree_element,
        output_tree_contains_relationship,
        config_source_element,
        *output_file_elements,
        *file_relationships,
    ]

    high_level_build_ancestorOf_relationship.to = [
        element for element in file_relationships if isinstance(element, Build)
    ]
    src_tree_contains_relationship.to = source_file_elements
    output_tree_contains_relationship.to = [config_source_element, *output_file_elements]

    # create Spdx graphs
    source_graph = SpdxGraph(source_spdx_document, agent, creation_info, source_sbom)
    build_graph = SpdxBuildGraph(
        build_spdx_document, agent, creation_info, build_sbom, root_file_elements, high_level_build_element
    )

    return source_graph, build_graph


def _shared_elements(spdx_id_generator: SpdxIdGenerator, created: datetime) -> tuple[SoftwareAgent, CreationInfo]:
    agent = SoftwareAgent(
        spdxId=spdx_id_generator.generate(),
        name="KernelSbom",
    )
    creation_info = CreationInfo(createdBy=[agent], created=created.strftime("%Y-%m-%dT%H:%M:%SZ"))
    return (agent, creation_info)


def _spdx_document_elements(
    spdx_id_generators: SpdxIdGeneratorCollection,
) -> tuple[SpdxDocument, SpdxDocument]:
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
    return source_spdx_document, build_spdx_document


def _sbom_elements(spdx_id_generators: SpdxIdGeneratorCollection) -> tuple[Sbom, Sbom]:
    source_sbom = Sbom(
        spdxId=spdx_id_generators.source.generate(),
        software_sbomType=["source"],
    )
    build_sbom = Sbom(
        spdxId=spdx_id_generators.build.generate(),
        software_sbomType=["build"],
    )
    return source_sbom, build_sbom


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


def _config_source_element(output_tree: PathStr, src_tree: PathStr, spdx_id_generator: SpdxIdGenerator) -> File:
    config_source_element = build_kernel_file_element(
        absolute_path=os.path.join(output_tree, ".config"),
        output_tree=output_tree,
        src_tree=src_tree,
        build_id_generator=spdx_id_generator,
        source_id_generator=spdx_id_generator,
    )
    return config_source_element


def _high_level_build_elements(
    build_type: str, build_id: str | None, config_source_element: File, spdx_id_generator: SpdxIdGenerator
) -> tuple[Build, Relationship]:
    build_spdxId = spdx_id_generator.generate()
    high_level_build_element = Build(
        spdxId=build_spdxId,
        build_buildType=build_type,
        build_buildId=build_id if build_id is not None else build_spdxId,
        build_environment=[
            DictionaryEntry(key=key, value=value)
            for key, value in Environment.KERNEL_BUILD_VARIABLES.items()
            if value is not None
        ],
        build_configSourceUri=config_source_element.spdxId,
        build_configSourceDigest=next(iter(config_source_element.verifiedUsing), None),
    )
    high_level_build_ancestorOf_relationship = Relationship(
        spdxId=spdx_id_generator.generate(),
        relationshipType="ancestorOf",
        from_=high_level_build_element,
        completeness="complete",
        to=[],
    )
    return (high_level_build_element, high_level_build_ancestorOf_relationship)


def _file_relationships(
    cmd_graph: CmdGraph,
    file_elements: Mapping[PathStr, File],
    build_type: str,
    build_id: str,
    spdx_id_generator: SpdxIdGenerator,
) -> list[Build | Relationship]:
    # Create a relationship between each node (output file) and its children (input files)
    build_and_relationship_elements: list[Build | Relationship] = []
    for node in iter_cmd_graph(cmd_graph):
        if next(node.children, None) is None:
            continue

        # .cmd file dependencies
        if node.cmd_file is not None:
            build_element = Build(
                spdxId=spdx_id_generator.generate(),
                build_buildType=build_type,
                build_buildId=build_id,
                comment=node.cmd_file.savedcmd,
            )
            hasInput_relationship = Relationship(
                spdxId=spdx_id_generator.generate(),
                relationshipType="hasInput",
                from_=build_element,
                to=[file_elements[child_node.absolute_path] for child_node in node.children],
            )
            hasOutput_relationship = Relationship(
                spdxId=spdx_id_generator.generate(),
                relationshipType="hasOutput",
                from_=build_element,
                to=[file_elements[node.absolute_path]],
            )
            build_and_relationship_elements += [build_element, hasInput_relationship, hasOutput_relationship]

        # incbin dependencies
        if len(node.incbin_dependencies) > 0:
            incbin_dependsOn_relationship = Relationship(
                spdxId=spdx_id_generator.generate(),
                relationshipType="dependsOn",
                comment="\n".join([incbin_dependency.full_statement for incbin_dependency in node.incbin_dependencies]),
                from_=file_elements[node.absolute_path],
                to=[
                    file_elements[incbin_depdendency.node.absolute_path]
                    for incbin_depdendency in node.incbin_dependencies
                ],
            )
            build_and_relationship_elements.append(incbin_dependsOn_relationship)

        # hardcoded dependencies
        if len(node.hardcoded_dependencies) > 0:
            hardcoded_dependency_relationship = Relationship(
                spdxId=spdx_id_generator.generate(),
                relationshipType="dependsOn",
                from_=file_elements[node.absolute_path],
                to=[file_elements[n.absolute_path] for n in node.hardcoded_dependencies],
            )
            build_and_relationship_elements.append(hardcoded_dependency_relationship)

    return build_and_relationship_elements
