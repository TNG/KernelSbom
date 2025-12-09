# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
from sbom.spdx import SpdxIdGenerator
from sbom.spdx.core import Element, NamespaceMap, Relationship, SpdxDocument
from sbom.spdx.simplelicensing import LicenseExpression
from sbom.spdx.software import File, Sbom
from sbom.spdx_graph.kernel_file import KernelFile
from sbom.spdx_graph.shared_spdx_elements import SharedSpdxElements
from sbom.spdx_graph.spdx_graph_model import SpdxGraph, SpdxIdGeneratorCollection


@dataclass
class SpdxSourceGraph(SpdxGraph):
    @classmethod
    def create(
        cls,
        source_files: list[KernelFile],
        shared_elements: SharedSpdxElements,
        spdx_id_generators: SpdxIdGeneratorCollection,
    ) -> "SpdxSourceGraph":
        # SpdxDocument
        source_spdx_document = SpdxDocument(
            spdxId=spdx_id_generators.source.generate(),
            profileConformance=["core", "software", "simpleLicensing"],
            namespaceMap=[
                NamespaceMap(prefix=generator.prefix, namespace=generator.namespace)
                for generator in [spdx_id_generators.source, spdx_id_generators.base]
                if generator.prefix is not None
            ],
        )

        # Sbom
        source_sbom = Sbom(
            spdxId=spdx_id_generators.source.generate(),
            software_sbomType=["source"],
        )

        # Src Tree Elements
        src_tree_element = File(
            spdxId=spdx_id_generators.source.generate(),
            name="$(src_tree)",
            software_fileKind="directory",
        )
        src_tree_contains_relationship = Relationship(
            spdxId=spdx_id_generators.source.generate(),
            relationshipType="contains",
            from_=src_tree_element,
            to=[],
        )

        # Source file elements
        source_file_elements: list[Element] = [file.spdx_file_element for file in source_files]

        # Source file license elements
        source_file_license_identifiers, source_file_license_relationships = source_file_license_elements(
            source_files, spdx_id_generators.source
        )

        # Update relationships
        source_spdx_document.rootElement = [source_sbom]
        source_sbom.rootElement = [src_tree_element]
        source_sbom.element = [
            src_tree_element,
            src_tree_contains_relationship,
            *source_file_elements,
            *source_file_license_identifiers,
            *source_file_license_relationships,
        ]
        src_tree_contains_relationship.to = source_file_elements

        source_graph = SpdxSourceGraph(
            source_spdx_document, shared_elements.agent, shared_elements.creation_info, source_sbom
        )
        return source_graph


def source_file_license_elements(
    files: list[KernelFile], spdx_id_generator: SpdxIdGenerator
) -> tuple[list[LicenseExpression], list[Relationship]]:
    source_file_license_identifiers: dict[str, LicenseExpression] = {}
    for file in files:
        if file.license_identifier is None or file.license_identifier in source_file_license_identifiers:
            continue
        source_file_license_identifiers[file.license_identifier] = LicenseExpression(
            spdxId=spdx_id_generator.generate(),
            simplelicensing_licenseExpression=file.license_identifier,
        )

    source_file_license_relationships = [
        Relationship(
            spdxId=spdx_id_generator.generate(),
            relationshipType="hasDeclaredLicense",
            from_=file.spdx_file_element,
            to=[source_file_license_identifiers[file.license_identifier]],
        )
        for file in files
        if file.license_identifier is not None
    ]
    return ([*source_file_license_identifiers.values()], source_file_license_relationships)
