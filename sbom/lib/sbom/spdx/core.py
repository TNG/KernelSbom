# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
import uuid

SPDX_SPEC_VERSION = "3.0.1"
SpdxId = str
ExternalIdentifierType = Literal["email", "gitoid", "urlScheme"]
HashAlgorithm = Literal["sha256", "sha512"]
ProfileIdentifierType = Literal["core", "software", "build", "lite", "simpleLicensing"]
RelationshipType = Literal["contains", "hasInput", "hasOutput"]
RelationshipCompleteness = Literal["complete", "incomplete", "noAssertion"]


def get_default_spdx_id(entity_type: str) -> SpdxId:
    return f"https://spdx.org/spdxdocs/{entity_type}-{uuid.uuid4()}"


@dataclass
class SpdxEntity:
    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass(kw_only=True)
class Element(SpdxEntity):
    type: str = field(init=False, default="Element")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("Element"))
    creationInfo: str = "_:creationinfo"


@dataclass(kw_only=True)
class ElementCollection(Element):
    type: str = field(init=False, default="ElementCollection")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("ElementCollection"))
    element: list[Element] = field(default_factory=list[Element])
    rootElement: list[Element] = field(default_factory=list[Element])
    profileConformance: list[ProfileIdentifierType] = field(default_factory=list[ProfileIdentifierType])

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["element"] = [element.spdxId for element in self.element]
        d["rootElement"] = [element.spdxId for element in self.rootElement]
        return d


@dataclass(kw_only=True)
class SpdxDocument(ElementCollection):
    type: str = field(init=False, default="SpdxDocument")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("Document"))


@dataclass(kw_only=True)
class Hash(SpdxEntity):
    type: str = field(init=False, default="Hash")
    hashValue: str
    algorithm: HashAlgorithm = "sha256"


@dataclass(kw_only=True)
class ExternalIdentifier(SpdxEntity):
    type: str = field(init=False, default="ExternalIdentifier")
    externalIdentifierType: ExternalIdentifierType
    identifier: str


@dataclass(kw_only=True)
class Agent(Element):
    type: str = field(init=False, default="Agent")
    spdxId: SpdxId = field(default_factory=lambda: get_default_spdx_id("Agent"))
    name: str
    externalIdentifier: list[ExternalIdentifier] = field(default_factory=list[ExternalIdentifier])


@dataclass(kw_only=True)
class CreationInfo(SpdxEntity):
    type: str = field(init=False, default="CreationInfo")
    spdxId: SpdxId = "_:creationinfo"
    specVersion: str = SPDX_SPEC_VERSION
    createdBy: list[Agent]
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["createdBy"] = [agent.spdxId for agent in self.createdBy]
        return d


@dataclass(kw_only=True)
class Relationship(Element):
    type: str = field(init=False, default="Relationship")
    spdxId: SpdxId = ""
    relationshipType: RelationshipType
    from_: SpdxId  # underscore because 'from' is a reserved keyword
    to: list[Element]
    completeness: RelationshipCompleteness | None = None

    def __post_init__(self):
        if self.spdxId == "":
            self.spdxId = get_default_spdx_id(f"Relationship/{self.relationshipType}")

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d["from"] = d.pop("from_")
        d["to"] = [element.spdxId for element in self.to]
        return d
