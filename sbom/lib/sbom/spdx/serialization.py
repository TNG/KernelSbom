# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


import json
from dataclasses import dataclass, field
from sbom.spdx.core import SPDX_SPEC_VERSION, SpdxEntity


@dataclass(kw_only=True)
class JsonLdDocument:
    context: str = f"https://spdx.org/rdf/{SPDX_SPEC_VERSION}/spdx-context.jsonld"
    graph: list[SpdxEntity] = field(default_factory=list[SpdxEntity])

    def to_jsonld(self):
        return json.dumps(
            {"@context": self.context, "@graph": [item.to_dict() for item in self.graph]},
            indent=2,
        )
