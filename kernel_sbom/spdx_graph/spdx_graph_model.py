# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
from kernel_sbom.spdx.core import CreationInfo, SoftwareAgent, SpdxDocument, SpdxObject
from kernel_sbom.spdx.software import Sbom
from kernel_sbom.spdx.spdxId import SpdxIdGenerator


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
class SpdxIdGeneratorCollection:
    """Holds SPDX ID generators for different document types to ensure globally unique SPDX IDs."""

    base: SpdxIdGenerator
    source: SpdxIdGenerator
    build: SpdxIdGenerator
    output: SpdxIdGenerator
