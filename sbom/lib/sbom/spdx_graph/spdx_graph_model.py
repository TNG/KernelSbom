# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass
from typing import Literal

from sbom.config import KernelSpdxDocumentKind
from sbom.spdx.build import Build
from sbom.spdx.core import CreationInfo, SoftwareAgent, SpdxDocument, SpdxObject
from sbom.spdx.software import File, Sbom
from sbom.spdx.spdxId import SpdxIdGenerator


@dataclass
class SpdxGraph:
    """Represents the complete graph of a single SPDX document."""

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


@dataclass
class SpdxBuildGraph(SpdxGraph):
    root_file_elements: list[File]
    high_level_build_element: Build


@dataclass
class SpdxIdGeneratorCollection:
    """Holds SPDX ID generators for different document types to ensure globally unique SPDX IDs."""

    base: SpdxIdGenerator
    source: SpdxIdGenerator
    build: SpdxIdGenerator
    output: SpdxIdGenerator

    def get(self, generator_kind: KernelSpdxDocumentKind | Literal["general"]) -> SpdxIdGenerator:
        generator_mapping: dict[KernelSpdxDocumentKind | Literal["general"], SpdxIdGenerator] = {
            "general": self.base,
            KernelSpdxDocumentKind.SOURCE: self.source,
            KernelSpdxDocumentKind.BUILD: self.build,
            KernelSpdxDocumentKind.OUTPUT: self.output,
        }
        return generator_mapping[generator_kind]
