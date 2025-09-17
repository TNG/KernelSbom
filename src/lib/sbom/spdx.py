# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
import json
import uuid

SPDX_SPEC_VERSION = "3.0.1"
SpdxId = str


def _generate_spdx_id(entity_type: str) -> SpdxId:
    return f"https://spdx.org/spdxdocs/{entity_type}-{uuid.uuid4()}"


@dataclass(kw_only=True)
class Hash:
    type: str = field(init=False, default="Hash")
    hashValue: str
    algorithm: str = "sha256"


@dataclass(kw_only=True)
class ExternalIdentifier:
    type: str = field(init=False, default="ExternalIdentifier")
    externalIdentifierType: str
    identifier: str


@dataclass(kw_only=True)
class Element:
    type: str = field(init=False, default="Element")
    spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("Element"))
    creationInfo: str = "_:creationinfo"


@dataclass(kw_only=True)
class Person(Element):
    type: str = field(init=False, default="Person")
    spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("Person"))
    name: Optional[str] = None
    externalIdentifier: list[ExternalIdentifier] = field(default_factory=list[ExternalIdentifier])


@dataclass(kw_only=True)
class CreationInfo:
    type: str = field(init=False, default="CreationInfo")
    id: str = "_:creationinfo"  # will serialize as '@id'
    specVersion: str = SPDX_SPEC_VERSION
    createdBy: list[SpdxId]
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


@dataclass(kw_only=True)
class SpdxDocument(Element):
    type: str = field(init=False, default="SpdxDocument")
    spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("Document"))
    profileConformance: list[str] = field(default_factory=list[str])
    rootElement: list[SpdxId] = field(default_factory=list[SpdxId])


# @dataclass(kw_only=True)
# class SoftwarePackage(Element):
#     type: str = field(init=False, default="software_Package")
#     spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("Package"))
#     name: str
#     software_packageVersion: Optional[str] = None
#     software_downloadLocation: Optional[str] = None
#     builtTime: Optional[str] = None
#     originatedBy: list[SpdxId] = field(default_factory=list)
#     verifiedUsing: list[Hash] = field(default_factory=list)

# @dataclass(kw_only=True)
# class SoftwareFile(Element):
#     type: str = field(init=False, default="software_File")
#     spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("File"))
#     name: str
#     verifiedUsing: list[Hash] = field(default_factory=list)
#     builtTime: Optional[str] = None
#     originatedBy: list[SpdxId] = field(default_factory=list)
#     software_primaryPurpose: Optional[str] = None
#     software_additionalPurpose: list[str] = field(default_factory=list)
#     software_copyrightText: Optional[str] = None


@dataclass(kw_only=True)
class Relationship(Element):
    type: str = field(init=False, default="Relationship")
    spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("Relationship"))
    relationshipType: str
    from_: SpdxId = field(metadata={"name": "from"})  # reserved keyword workaround
    to: list[SpdxId]
    completeness: Optional[str] = None


@dataclass(kw_only=True)
class SoftwareSbom(Element):
    type: str = field(init=False, default="software_Sbom")
    spdxId: SpdxId = field(default_factory=lambda: _generate_spdx_id("BOM"))
    rootElement: list[SpdxId] = field(default_factory=list[SpdxId])
    element: list[SpdxId] = field(default_factory=list[SpdxId])
    software_sbomType: list[str] = field(default_factory=list[str])


@dataclass(kw_only=True)
class JsonLdDocument:
    context: str = f"https://spdx.org/rdf/{SPDX_SPEC_VERSION}/spdx-context.jsonld"
    graph: list[Any] = field(default_factory=list[Any])

    def to_json(self):
        return json.dumps(
            {"@context": self.context, "@graph": [asdict(item) for item in self.graph]},
            indent=2,
        )
