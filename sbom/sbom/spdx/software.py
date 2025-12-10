# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass, field
from typing import Literal
from sbom.spdx.core import Artifact, ElementCollection, IntegrityMethod


SbomType = Literal["source", "build"]
FileKindType = Literal["file", "directory"]
SoftwarePurpose = Literal[
    "source",
    "archive",
    "library",
    "file",
    "data",
    "configuration",
    "executable",
    "module",
    "application",
    "documentation",
    "other",
]
ContentIdentifierType = Literal["gitoid", "swhid"]


@dataclass(kw_only=True)
class Sbom(ElementCollection):
    type: str = field(init=False, default="software_Sbom")
    software_sbomType: list[SbomType] = field(default_factory=list[SbomType])


@dataclass(kw_only=True)
class ContentIdentifier(IntegrityMethod):
    type: str = field(init=False, default="software_ContentIdentifier")
    software_contentIdentifierType: ContentIdentifierType
    software_contentIdentifierValue: str


@dataclass(kw_only=True)
class SoftwareArtifact(Artifact):
    type: str = field(init=False, default="software_Artifact")
    software_primaryPurpose: SoftwarePurpose | None = None
    software_additionalPurpose: list[SoftwarePurpose] = field(default_factory=list[SoftwarePurpose])
    software_copyrightText: str | None = None
    software_contentIdentifier: list[ContentIdentifier] = field(default_factory=list[ContentIdentifier])


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
