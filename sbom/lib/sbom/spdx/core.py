# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from sbom.spdx.spdxId import SpdxId, generate_spdx_id

SPDX_SPEC_VERSION = "3.0.1"
ExternalIdentifierType = Literal["email", "gitoid", "urlScheme"]
HashAlgorithm = Literal["sha256", "sha512"]
ProfileIdentifierType = Literal["core", "software", "build", "lite", "simpleLicensing"]
RelationshipType = Literal["contains", "generates", "hasDeclaredLicense", "hasInput", "hasOutput"]
RelationshipCompleteness = Literal["complete", "incomplete", "noAssertion"]


@dataclass
class SpdxObject:
    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass(kw_only=True)
class Hash(SpdxObject):
    type: str = field(init=False, default="Hash")
    hashValue: str
    algorithm: HashAlgorithm


@dataclass(kw_only=True)
class Element(SpdxObject):
    type: str = field(init=False, default="Element")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("Element"))
    creationInfo: str = "_:creationinfo"
    name: str | None = None
    verifiedUsing: list[Hash] = field(default_factory=list[Hash])
    comment: str | None = None


@dataclass(kw_only=True)
class ElementCollection(Element):
    type: str = field(init=False, default="ElementCollection")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("ElementCollection"))
    element: list[Element] = field(default_factory=list[Element])
    rootElement: list[Element] = field(default_factory=list[Element])
    profileConformance: list[ProfileIdentifierType] = field(default_factory=list[ProfileIdentifierType])

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        if self.element:
            d["element"] = [element.spdxId for element in self.element]
        if self.rootElement:
            d["rootElement"] = [element.spdxId for element in self.rootElement]
        return d


@dataclass(kw_only=True)
class SpdxDocument(ElementCollection):
    type: str = field(init=False, default="SpdxDocument")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("Document"))


@dataclass(kw_only=True)
class ExternalIdentifier(SpdxObject):
    type: str = field(init=False, default="ExternalIdentifier")
    externalIdentifierType: ExternalIdentifierType
    identifier: str


@dataclass(kw_only=True)
class Agent(Element):
    type: str = field(init=False, default="Agent")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("Agent"))
    externalIdentifier: list[ExternalIdentifier] = field(default_factory=list[ExternalIdentifier])


@dataclass(kw_only=True)
class SoftwareAgent(Agent):
    type: str = field(init=False, default="SoftwareAgent")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("SoftwareAgent"))


@dataclass(kw_only=True)
class CreationInfo(SpdxObject):
    type: str = field(init=False, default="CreationInfo")
    spdxId: SpdxId = "_:creationinfo"
    specVersion: str = SPDX_SPEC_VERSION
    createdBy: list[Agent]
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        if self.createdBy:
            d["createdBy"] = [agent.spdxId for agent in self.createdBy]
        return d


@dataclass(kw_only=True)
class Relationship(Element):
    type: str = field(init=False, default="Relationship")
    spdxId: SpdxId = ""  # set in __post_init__
    relationshipType: RelationshipType
    from_: Element  # underscore because 'from' is a reserved keyword
    to: list[Element]
    completeness: RelationshipCompleteness | None = None

    def __post_init__(self):
        if self.spdxId == "":
            self.spdxId = generate_spdx_id(f"Relationship_{self.relationshipType}")

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.pop("from_")
        d.pop("to")
        d["from"] = self.from_.spdxId
        d["to"] = [element.spdxId for element in self.to]
        return d


@dataclass(kw_only=True)
class Artifact(Element):
    type: str = field(init=False, default="Artifact")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("Artifact"))
    builtTime: str | None = None
    originatedBy: list[Agent] = field(default_factory=list[Agent])

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        if self.originatedBy:
            d["originatedBy"] = [agent.spdxId for agent in self.originatedBy]
        return d
