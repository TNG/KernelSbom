# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass, field
from typing import Literal
from sbom.spdx.core import Artifact, ElementCollection


SbomType = Literal["build"]
FileKindType = Literal["file", "directory"]
SoftwarePurpose = Literal[
    "source", "archive", "library", "file", "data", "configuration", "executable", "module", "other"
]


@dataclass(kw_only=True)
class Sbom(ElementCollection):
    type: str = field(init=False, default="software_Sbom")
    software_sbomType: list[SbomType] = field(default_factory=list[SbomType])


@dataclass(kw_only=True)
class SoftwareArtifact(Artifact):
    type: str = field(init=False, default="software_Artifact")
    software_primaryPurpose: SoftwarePurpose | None = None
    software_additionalPurpose: list[SoftwarePurpose] = field(default_factory=list[SoftwarePurpose])
    software_copyrightText: str | None = None


@dataclass(kw_only=True)
class Package(SoftwareArtifact):
    type: str = field(init=False, default="software_Package")
    name: str  # type: ignore
    software_packageVersion: str | None = None
    software_downloadLocation: str | None = None


@dataclass(kw_only=True)
class File(SoftwareArtifact):
    type: str = field(init=False, default="software_File")
    name: str  # type: ignore
    software_fileKind: FileKindType | None = None
