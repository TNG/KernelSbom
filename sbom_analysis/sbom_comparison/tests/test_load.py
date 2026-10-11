# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""Unit tests for the deterministic id rewriting and unchanged filtering."""

import unittest

from sbom_compare.load import compare_document_set, element_ident, normalize_document_set

DOC = {
    "type": "SpdxDocument",
    "spdxId": "b:0",
    "creationInfo": "_:creationinfo",
    "name": "doc",
}
AGENT = {
    "type": "SoftwareAgent",
    "spdxId": "p:0",
    "creationInfo": "_:creationinfo",
    "name": "KernelSbom",
}
CREATION_INFO = {
    "type": "CreationInfo",
    "@id": "_:creationinfo",
    "specVersion": "3.0.1",
    "createdBy": ["p:0"],
    "created": "2026-01-01T00:00:00Z",
}


def file_element(spdx_id: str, name: str) -> dict:
    return {"type": "software_File", "spdxId": spdx_id, "creationInfo": "_:creationinfo", "name": name}


def build_element(spdx_id: str, comment: str) -> dict:
    return {"type": "build_Build", "spdxId": spdx_id, "creationInfo": "_:creationinfo", "comment": comment}


def relationship_element(spdx_id: str, from_id: str, to_ids: list[str]) -> dict:
    return {
        "type": "Relationship",
        "spdxId": spdx_id,
        "creationInfo": "_:creationinfo",
        "relationshipType": "contains",
        "from": from_id,
        "to": to_ids,
    }


def document(elements: list[dict]) -> dict:
    return {"@context": ["https://example.org/spdx-context.jsonld", {}], "@graph": elements}


class TestDeterministicIds(unittest.TestCase):
    def test_ids_stable_under_renumbering(self):
        """Same content with different generator numbering yields same ids."""
        reference = document(
            [
                DOC,
                AGENT,
                CREATION_INFO,
                file_element("b:1", "kernel/sched/core.c"),
                build_element("b:2", "gcc -c kernel/sched/core.c"),
                relationship_element("b:3", "b:2", ["b:1"]),
            ]
        )
        # Candidate: an extra element shifts all numbering by one.
        candidate = document(
            [
                DOC,
                AGENT,
                CREATION_INFO,
                file_element("b:9", "extra.o"),
                file_element("b:2", "kernel/sched/core.c"),
                build_element("b:3", "gcc -c kernel/sched/core.c"),
                relationship_element("b:4", "b:3", ["b:2"]),
            ]
        )
        reference_ids = normalize_document_set({"sbom-build.spdx.json": reference})
        candidate_ids = normalize_document_set({"sbom-build.spdx.json": candidate})
        reference_graph = reference_ids["sbom-build.spdx.json"]["@graph"]
        candidate_graph = candidate_ids["sbom-build.spdx.json"]["@graph"]

        def id_of_name(graph, value):
            return next(
                e["spdxId"] for e in graph if value in (e.get("name"), e.get("comment"))
            )

        self.assertEqual(
            id_of_name(reference_graph, "kernel/sched/core.c"),
            id_of_name(candidate_graph, "kernel/sched/core.c"),
        )
        # The relationship id is stable too, because its endpoints resolve to
        # the same deterministic ids.
        self.assertEqual(
            id_of_name(reference_graph, "gcc -c kernel/sched/core.c"),
            id_of_name(candidate_graph, "gcc -c kernel/sched/core.c"),
        )

    def test_references_are_rewritten(self):
        doc = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        DOC,
                        AGENT,
                        CREATION_INFO,
                        file_element("b:1", "kernel/sched/core.c"),
                        relationship_element("b:2", "b:1", ["b:1"]),
                    ]
                )
            }
        )
        graph = doc["sbom-build.spdx.json"]["@graph"]
        file_id = next(e["spdxId"] for e in graph if e.get("name") == "kernel/sched/core.c")
        relationship = next(e for e in graph if e.get("type") == "Relationship")
        self.assertEqual(relationship["from"], file_id)
        self.assertEqual(relationship["to"], [file_id])
        self.assertNotEqual(relationship["spdxId"], "b:2")

    def test_changed_relationship_endpoints_change_id(self):
        """A relationship whose endpoints resolve differently gets a new id."""
        reference = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        file_element("b:1", "a.c"),
                        relationship_element("b:2", "b:1", []),
                    ]
                )
            }
        )
        candidate = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        file_element("b:1", "b.c"),
                        relationship_element("b:2", "b:1", []),
                    ]
                )
            }
        )
        rel_reference = next(
            e
            for e in reference["sbom-build.spdx.json"]["@graph"]
            if e.get("type") == "Relationship"
        )
        rel_candidate = next(
            e
            for e in candidate["sbom-build.spdx.json"]["@graph"]
            if e.get("type") == "Relationship"
        )
        self.assertNotEqual(rel_reference["spdxId"], rel_candidate["spdxId"])

    def test_changed_to_targets_keep_relationship_id(self):
        """A relationship that gains or loses `to` targets is changed, not
        removed + added: its identity is type and source only."""
        reference = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        file_element("b:1", "a.c"),
                        relationship_element("b:2", "b:1", ["b:1"]),
                    ]
                )
            }
        )
        candidate = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        file_element("b:1", "a.c"),
                        relationship_element("b:2", "b:1", []),
                    ]
                )
            }
        )
        data = compare_document_set(reference, candidate)["sbom-build.spdx.json"]
        self.assertEqual(data["removed"], [])
        self.assertEqual(data["added"], [])
        self.assertEqual(len(data["changed"]), 1)


class TestCompareDocumentSet(unittest.TestCase):
    def setUp(self):
        self.reference = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        DOC,
                        AGENT,
                        CREATION_INFO,
                        file_element("b:1", "kernel/sched/core.c"),
                        file_element("b:2", "init/main.c"),
                        build_element("b:3", "gcc -c kernel/sched/core.c"),
                        relationship_element("b:4", "b:3", ["b:1"]),
                    ]
                )
            }
        )
        self.candidate = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [
                        DOC,
                        AGENT,
                        {**CREATION_INFO, "created": "2026-02-02T00:00:00Z"},
                        file_element("b:1", "kernel/sched/core.c"),
                        file_element("b:5", "drivers/net/loopback.c"),
                        build_element("b:6", "gcc -c kernel/sched/core.c -O2"),
                        relationship_element("b:7", "b:6", ["b:1"]),
                    ]
                )
            }
        )
        self.result = compare_document_set(self.reference, self.candidate)

    def ids_of(self, entries):
        """Deterministic ids of elements; `changed` entries are (ref, cand) pairs."""
        elements = [entry[0] if isinstance(entry, tuple) else entry for entry in entries]
        return {element_ident(element) for element in elements}

    def test_classification(self):
        data = self.result["sbom-build.spdx.json"]
        graph_reference = self.reference["sbom-build.spdx.json"]["@graph"]
        graph_candidate = self.candidate["sbom-build.spdx.json"]["@graph"]
        id_reference = {
            e[k]: e["spdxId"]
            for e in graph_reference
            for k in ("name", "comment")
            if k in e
        }
        id_candidate = {
            e[k]: e["spdxId"]
            for e in graph_candidate
            for k in ("name", "comment")
            if k in e
        }

        # "init/main.c" removed, "drivers/net/loopback.c" added.
        self.assertIn(id_reference["init/main.c"], self.ids_of(data["removed"]))
        self.assertIn(id_candidate["drivers/net/loopback.c"], self.ids_of(data["added"]))

        # Elements whose identity is their content (build command, relationship
        # endpoints) appear as removed + added, like a modified line in git.
        build_reference = id_reference["gcc -c kernel/sched/core.c"]
        build_candidate = id_candidate["gcc -c kernel/sched/core.c -O2"]
        rel_reference = next(e["spdxId"] for e in graph_reference if e.get("type") == "Relationship")
        rel_candidate = next(e["spdxId"] for e in graph_candidate if e.get("type") == "Relationship")
        self.assertEqual(
            {build_reference, rel_reference},
            self.ids_of(data["removed"]) & {build_reference, rel_reference},
        )
        self.assertEqual(
            {build_candidate, rel_candidate},
            self.ids_of(data["added"]) & {build_candidate, rel_candidate},
        )

        # Only elements with stable identity but changed content appear as
        # "changed" — here the creation timestamp of the shared CreationInfo.
        self.assertEqual({"_:creationinfo"}, self.ids_of(data["changed"]))

        # The unchanged file and document-level boilerplate are filtered out.
        unchanged_ids = (
            id_reference["kernel/sched/core.c"],
            id_reference["doc"],
            id_reference["KernelSbom"],
        )
        for unchanged in unchanged_ids:
            self.assertNotIn(unchanged, self.ids_of(data["changed"]))
            self.assertNotIn(unchanged, self.ids_of(data["added"]))
            self.assertNotIn(unchanged, self.ids_of(data["removed"]))

    def test_filtered_elements_contain_only_changes(self):
        data = self.result["sbom-build.spdx.json"]
        names_of = lambda elements: [e.get("name") for e in elements]
        reference_side = names_of(data["removed"]) + [
            ref.get("name") for ref, _ in data["changed"]
        ]
        candidate_side = names_of(data["added"]) + [
            cand.get("name") for _, cand in data["changed"]
        ]
        self.assertNotIn("kernel/sched/core.c", reference_side)
        self.assertNotIn("kernel/sched/core.c", candidate_side)
        self.assertIn("init/main.c", reference_side)
        self.assertNotIn("init/main.c", candidate_side)
        self.assertIn("drivers/net/loopback.c", candidate_side)
        self.assertIn(
            "gcc -c kernel/sched/core.c -O2",
            [e.get("comment") for e in data["added"]]
            + [cand.get("comment") for _, cand in data["changed"]],
        )

    def test_identical_documents_produce_empty_sets(self):
        result = compare_document_set(self.reference, self.reference)
        data = result["sbom-build.spdx.json"]
        self.assertEqual(data["added"], [])
        self.assertEqual(data["removed"], [])
        self.assertEqual(data["changed"], [])


if __name__ == "__main__":
    unittest.main()