# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from sbom.spdx.build import Build
from sbom.spdx.core import SpdxDocument, SpdxObject
from sbom.spdx.spdxId import SpdxId
from sbom.spdx_graph.spdx_graph_model import SpdxIdGeneratorCollection


def expand_spdxIds_for_non_expandable_properties(
    spdx_graph: list[SpdxObject], spdx_id_generators: SpdxIdGeneratorCollection
) -> list[SpdxObject]:
    """
    The SPDX JSON-LD context https://spdx.github.io/spdx-spec/v3.0.1/rdf/spdx-context.jsonld does not support expanding values for properties with Literal types:
    - ExternalMap.externalSpdxId of type http://www.w3.org/2001/XMLSchema#anyURI
    - Build.buildId of type http://www.w3.org/2001/XMLSchema#string
    - Build.configSourceUri http://www.w3.org/2001/XMLSchema#anyURI
    This function expands compact spdxIds used for these properties.
    """

    def expand(compact_id: SpdxId) -> SpdxId:
        for generator in [spdx_id_generators.source, spdx_id_generators.build, spdx_id_generators.output]:
            if generator.prefix and compact_id.startswith(f"{generator.prefix}:"):
                return compact_id.replace(f"{generator.prefix}:", generator.namespace)
        return compact_id

    for spdx_object in spdx_graph:
        match spdx_object:
            case SpdxDocument():
                for external_map in spdx_object.import_:
                    external_map.externalSpdxId = expand(external_map.externalSpdxId)
            case Build():
                spdx_object.build_buildId = expand(spdx_object.build_buildId)
                spdx_object.build_configSourceUri = [expand(uri) for uri in spdx_object.build_configSourceUri]
            case _:
                continue

    return spdx_graph
