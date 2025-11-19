# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from sbom.spdx import SpdxId, SpdxIdGenerator

SPDX_SPEC_VERSION = "3.0.1"
ExternalIdentifierType = Literal["email", "gitoid", "urlScheme"]
HashAlgorithm = Literal["sha256", "sha512"]
ProfileIdentifierType = Literal["core", "software", "build", "lite", "simpleLicensing"]
RelationshipType = Literal["contains", "generates", "hasDeclaredLicense", "hasInput", "hasOutput"]
RelationshipCompleteness = Literal["complete", "incomplete", "noAssertion"]


@dataclass
class SpdxObject:
    def to_dict(self) -> dict[str, Any]:
        def _to_dict(v: Any):
            return v.to_dict() if hasattr(v, "to_dict") else v

        d: dict[str, Any] = {}
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if not value:
                continue

            if isinstance(value, Element):
                d[field_name] = value.spdxId
            elif isinstance(value, list) and len(value) > 0 and isinstance(value[0], Element):  # type: ignore
                value: list[Element] = value
                d[field_name] = [v.spdxId for v in value]
            else:
                d[field_name] = [_to_dict(v) for v in value] if isinstance(value, list) else _to_dict(value)  # type: ignore
        return d


@dataclass(kw_only=True)
class IntegrityMethod(SpdxObject): ...


@dataclass(kw_only=True)
class Hash(IntegrityMethod):
    type: str = field(init=False, default="Hash")
    hashValue: str
    algorithm: HashAlgorithm


@dataclass(kw_only=True)
class Element(SpdxObject):
    type: str = field(init=False, default="Element")
    spdxId: SpdxId = field(default_factory=lambda: SpdxIdGenerator.generate())
    creationInfo: str = "_:creationinfo"
    name: str | None = None
    verifiedUsing: list[Hash] = field(default_factory=list[Hash])
    comment: str | None = None


@dataclass(kw_only=True)
class ElementCollection(Element):
    type: str = field(init=False, default="ElementCollection")
    element: list[Element] = field(default_factory=list[Element])
    rootElement: list[Element] = field(default_factory=list[Element])
    profileConformance: list[ProfileIdentifierType] = field(default_factory=list[ProfileIdentifierType])


@dataclass(kw_only=True)
class SpdxDocument(ElementCollection):
    type: str = field(init=False, default="SpdxDocument")


@dataclass(kw_only=True)
class ExternalIdentifier(SpdxObject):
    type: str = field(init=False, default="ExternalIdentifier")
    externalIdentifierType: ExternalIdentifierType
    identifier: str


@dataclass(kw_only=True)
class Agent(Element):
    type: str = field(init=False, default="Agent")
    externalIdentifier: list[ExternalIdentifier] = field(default_factory=list[ExternalIdentifier])


@dataclass(kw_only=True)
class SoftwareAgent(Agent):
    type: str = field(init=False, default="SoftwareAgent")


@dataclass(kw_only=True)
class CreationInfo(SpdxObject):
    type: str = field(init=False, default="CreationInfo")
    id: SpdxId = "_:creationinfo"
    specVersion: str = SPDX_SPEC_VERSION
    createdBy: list[Agent]
    created: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def to_dict(self) -> dict[str, Any]:
        return {("@id" if k == "id" else k): v for k, v in super().to_dict().items()}


@dataclass(kw_only=True)
class Relationship(Element):
    type: str = field(init=False, default="Relationship")
    relationshipType: RelationshipType
    from_: Element  # underscore because 'from' is a reserved keyword
    to: list[Element]
    completeness: RelationshipCompleteness | None = None

    def to_dict(self) -> dict[str, Any]:
        return {("from" if k == "from_" else k): v for k, v in super().to_dict().items()}


@dataclass(kw_only=True)
class Artifact(Element):
    type: str = field(init=False, default="Artifact")
    builtTime: str | None = None
    originatedBy: list[Agent] = field(default_factory=list[Agent])
