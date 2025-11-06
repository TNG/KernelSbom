# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from sbom.spdx.core import SPDX_SPEC_VERSION, SpdxObject


@dataclass(kw_only=True)
class JsonLdDocument:
    context: str = f"https://spdx.org/rdf/{SPDX_SPEC_VERSION}/spdx-context.jsonld"
    graph: list[SpdxObject] = field(default_factory=list[SpdxObject])

    def to_dict(self) -> dict[str, Any]:
        return {
            "@context": self.context,
            "@graph": [item.to_dict() for item in self.graph],
        }

    def save(self, path: Path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
