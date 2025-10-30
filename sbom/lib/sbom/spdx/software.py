# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass, field
from typing import Literal
from sbom.spdx.core import Element, ElementCollection, Hash, SpdxId, get_default_spdx_id

SbomType = Literal["build"]


@dataclass(kw_only=True)
class Sbom(ElementCollection):
    type: str = field(init=False, default="software_Sbom")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("Sbom"))
    software_sbomType: list[SbomType] = field(default_factory=list[SbomType])


@dataclass(kw_only=True)
class Package(Element):
    type: str = field(init=False, default="software_Package")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("Package"))
    name: str
    software_packageVersion: str | None = None
    software_downloadLocation: str | None = None
    builtTime: str | None = None
    originatedBy: list[SpdxId] = field(default_factory=list[SpdxId])
    verifiedUsing: list[Hash] = field(default_factory=list[Hash])


@dataclass(kw_only=True)
class File(Element):
    type: str = field(init=False, default="software_File")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("File"))
    name: str
    verifiedUsing: list[Hash] = field(default_factory=list[Hash])
    builtTime: str | None = None
    originatedBy: list[SpdxId] = field(default_factory=list[SpdxId])
    software_primaryPurpose: str | None = None
    software_additionalPurpose: list[str] = field(default_factory=list[str])
    software_copyrightText: str | None = None
