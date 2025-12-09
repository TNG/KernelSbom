# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


import json
from typing import Any
from sbom.path_utils import PathStr
from sbom.spdx.core import SPDX_SPEC_VERSION, SpdxDocument, SpdxObject


class JsonLdSpdxDocument:
    context: list[str | dict[str, str]]
    graph: list[SpdxObject]

    def __init__(self, graph: list[SpdxObject]) -> None:
        self.graph = graph
        spdx_document = next(element for element in graph if isinstance(element, SpdxDocument))
        self.context = [
            f"https://spdx.org/rdf/{SPDX_SPEC_VERSION}/spdx-context.jsonld",
            {namespaceMap.prefix: namespaceMap.namespace for namespaceMap in spdx_document.namespaceMap},
        ]
        spdx_document.namespaceMap = []

    def to_dict(self) -> dict[str, Any]:
        return {
            "@context": self.context,
            "@graph": [item.to_dict() for item in self.graph],
        }

    def save(self, path: PathStr, prettify: bool) -> None:
        with open(path, "w", encoding="utf-8") as f:
            if prettify:
                json.dump(self.to_dict(), f, indent=2)
            else:
                json.dump(self.to_dict(), f, separators=(",", ":"))
