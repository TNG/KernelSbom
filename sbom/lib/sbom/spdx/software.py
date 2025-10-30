# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass, field
from typing import Literal
from sbom.spdx.core import Artifact, ElementCollection, SpdxId, get_default_spdx_id

SbomType = Literal["build"]


@dataclass(kw_only=True)
class Sbom(ElementCollection):
    type: str = field(init=False, default="software_Sbom")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("software_Sbom"))
    software_sbomType: list[SbomType] = field(default_factory=list[SbomType])


@dataclass(kw_only=True)
class SoftwareArtifact(Artifact):
    type: str = field(init=False, default="software_Artifact")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("software_Artifact"))
    software_additionalPurpose: list[str] = field(default_factory=list[str])
    software_copyrightText: str | None = None
    software_primaryPurpose: str | None = None


@dataclass(kw_only=True)
class Package(SoftwareArtifact):
    type: str = field(init=False, default="software_Package")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("software_Package"))
    name: str
    software_packageVersion: str | None = None
    software_downloadLocation: str | None = None


@dataclass(kw_only=True)
class File(SoftwareArtifact):
    type: str = field(init=False, default="software_File")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("software_File"))
    name: str
