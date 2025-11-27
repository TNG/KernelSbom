# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import os
from datetime import datetime
from typing import Protocol
from sbom.environment import Environment
from sbom.path_utils import PathStr
from sbom.spdx.core import ExternalMap, NamespaceMap, Relationship, SpdxDocument
from sbom.spdx.simplelicensing import LicenseExpression
from sbom.spdx.software import Package, Sbom
from sbom.spdx_graph.spdx_graph_model import SpdxBuildGraph, SpdxGraph, SpdxIdGeneratorCollection


class SpdxOutputGraphConfig(Protocol):
    output_tree: PathStr
    src_tree: PathStr
    created: datetime
    build_type: str
    build_id: str | None
    package_license: str
    package_version: str | None
    package_copyright_text: str | None


def create_output_graph(
    build_graph: SpdxBuildGraph,
    spdx_id_generators: SpdxIdGeneratorCollection,
    config: SpdxOutputGraphConfig,
) -> SpdxGraph:
    # SpdxDocument
    spdx_document = SpdxDocument(
        spdxId=spdx_id_generators.output.generate(),
        profileConformance=["core", "software", "build", "simpleLicensing"],
        namespaceMap=[
            NamespaceMap(prefix=generator.prefix, namespace=generator.namespace)
            for generator in [spdx_id_generators.output, spdx_id_generators.build, spdx_id_generators.base]
            if generator.prefix is not None
        ],
    )

    # Sbom
    sbom = Sbom(
        spdxId=spdx_id_generators.output.generate(),
        software_sbomType=["build"],
    )

    # Package elements
    package_elements = [
        Package(
            spdxId=spdx_id_generators.output.generate(),
            name=_get_package_name(file.name),
            software_packageVersion=config.package_version,
            software_copyrightText=config.package_copyright_text,
            originatedBy=[build_graph.agent],
            comment=f"Architecture={arch}" if (arch := Environment.ARCH or Environment.SRCARCH) else None,
            software_primaryPurpose=file.software_primaryPurpose,
        )
        for file in build_graph.root_file_elements
    ]
    package_hasDistributionArtifact_file_relationships = [
        Relationship(
            spdxId=spdx_id_generators.output.generate(),
            relationshipType="hasDistributionArtifact",
            from_=package,
            to=[file],
        )
        for package, file in zip(package_elements, build_graph.root_file_elements)
    ]
    package_license_expression = LicenseExpression(
        spdxId=spdx_id_generators.output.generate(),
        simplelicensing_licenseExpression=config.package_license,
    )
    package_hasDeclaredLicense_relationships = [
        Relationship(
            spdxId=spdx_id_generators.output.generate(),
            relationshipType="hasDeclaredLicense",
            from_=package,
            to=[package_license_expression],
        )
        for package in package_elements
    ]

    # Update relationships
    spdx_document.rootElement = [sbom]
    spdx_document.import_ = [
        ExternalMap(externalSpdxId=build_graph.high_level_build_element.spdxId),
        *(ExternalMap(externalSpdxId=file.spdxId) for file in build_graph.root_file_elements),
    ]

    sbom.rootElement = [*package_elements]
    sbom.element = [
        build_graph.high_level_build_element,
        *package_elements,
        *package_hasDistributionArtifact_file_relationships,
        *package_hasDeclaredLicense_relationships,
        package_license_expression,
        *build_graph.root_file_elements,
    ]

    output_graph = SpdxGraph(spdx_document, build_graph.agent, build_graph.creation_info, sbom)
    return output_graph


def _get_package_name(filename: str) -> str:
    KERNEL_FILENAMES = ["bzImage", "Image"]
    basename = os.path.basename(filename)
    return f"Linux Kernel ({basename})" if basename in KERNEL_FILENAMES else basename
