# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


from dataclasses import dataclass, field
import json
from sbom.cmd.cmd_graph import CmdGraph
from sbom.spdx.core import (
    SPDX_SPEC_VERSION,
    SpdxEntity,
    Agent,
    ExternalIdentifier,
    CreationInfo,
    Hash,
    Relationship,
    SpdxDocument,
)
from sbom.spdx.software import Package, File, Sbom


@dataclass(kw_only=True)
class JsonLdDocument:
    context: str = f"https://spdx.org/rdf/{SPDX_SPEC_VERSION}/spdx-context.jsonld"
    graph: list[SpdxEntity] = field(default_factory=list[SpdxEntity])

    def to_jsonld(self):
        return json.dumps(
            {"@context": self.context, "@graph": [item.to_dict() for item in self.graph]},
            indent=2,
        )

    @staticmethod
    def from_cmd_graph(cmd_graph: CmdGraph) -> "JsonLdDocument":
        agent = Agent(
            name="Luis Augenstein",
            externalIdentifier=[
                ExternalIdentifier(externalIdentifierType="email", identifier="luis.augenstein@tngtech.com")
            ],
        )
        creation_info = CreationInfo(createdBy=[agent])

        software_package = Package(
            name="amazing-widget",
            software_packageVersion="1.0",
            software_downloadLocation="http://dl.example.com/amazing-widget_1.0.0.tar",
            builtTime="2024-03-06T00:00:00Z",
            originatedBy=[agent.spdxId],
            verifiedUsing=[Hash(hashValue="f3f60ce8615d1cfb3f6d7d149699ab53170ce0b8f24f841fb616faa50151082d")],
        )
        software_file1 = File(
            name="/usr/bin/amazing-widget",
            builtTime="2024-03-05T00:00:00Z",
            originatedBy=[agent.spdxId],
            software_primaryPurpose="executable",
            software_additionalPurpose=["application"],
            software_copyrightText="Copyright 2024, Joshua Watt",
            verifiedUsing=[Hash(hashValue="ee4f96ed470ea288be281407dacb380fd355886dbd52c8c684dfec3a90e78f45")],
        )
        software_file2 = File(
            name="/etc/amazing-widget.cfg",
            builtTime="2024-03-05T00:00:00Z",
            originatedBy=[agent.spdxId],
            software_primaryPurpose="configuration",
            verifiedUsing=[Hash(hashValue="ee4f96ed470ea288be281407dacb380fd355886dbd52c8c684dfec3a90e78f45")],
        )
        relationship = Relationship(
            relationshipType="contains",
            from_=software_package.spdxId,
            to=[software_file1, software_file2],
            completeness="complete",
        )

        software_sbom = Sbom(
            software_sbomType=["build"],
            rootElement=[software_package],
            element=[software_file1, software_file2],
        )
        spdx_document = SpdxDocument(profileConformance=["core", "software", "build"], rootElement=[software_sbom])
        return JsonLdDocument(
            graph=[
                agent,
                creation_info,
                software_package,
                software_file1,
                software_file2,
                relationship,
                software_sbom,
                spdx_document,
            ]
        )
