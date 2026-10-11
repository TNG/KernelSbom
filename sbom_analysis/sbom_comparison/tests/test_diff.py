# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""Unit tests for the semantic unified diff assembly."""

import unittest

from sbom_compare.diff import semantic_unified_diff
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


def document(elements: list[dict]) -> dict:
    return {"@context": ["https://example.org/spdx-context.jsonld", {}], "@graph": elements}


class TestSemanticUnifiedDiff(unittest.TestCase):
    def setUp(self):
        self.reference = normalize_document_set(
            {
                "sbom-build.spdx.json": document(
                    [DOC, AGENT, CREATION_INFO, file_element("b:1", "kernel/sched/core.c"), file_element("b:2", "init/main.c")]
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
                        file_element("b:3", "drivers/net/loopback.c"),
                    ]
                )
            }
        )
        self.data = compare_document_set(self.reference, self.candidate)["sbom-build.spdx.json"]

    def lines_of(self, lines: list[str], prefix: str) -> list[str]:
        return [line for line in lines if line.startswith(prefix) and not line.startswith(("+++", "---"))]

    def test_removed_element_is_minus_block(self):
        diff = semantic_unified_diff(self.data, "reference/x", "candidate/x")
        minus = self.lines_of(diff, "-")
        self.assertTrue(any('"name": "init/main.c"' in line for line in minus))

    def test_added_element_is_plus_block(self):
        diff = semantic_unified_diff(self.data, "reference/x", "candidate/x")
        plus = self.lines_of(diff, "+")
        self.assertTrue(any('"name": "drivers/net/loopback.c"' in line for line in plus))

    def test_changed_element_is_minus_plus_pair_in_one_hunk(self):
        diff = semantic_unified_diff(self.data, "reference/x", "candidate/x")
        changed_id = next(element_ident(ref) for ref, _ in self.data["changed"])
        header_index = diff.index(f"@@ {changed_id} @@")
        hunk = []
        for line in diff[header_index + 1 :]:
            if line.startswith("@@"):
                break
            hunk.append(line)
        self.assertTrue(any(line.startswith("-") for line in hunk))
        self.assertTrue(any(line.startswith("+") for line in hunk))
        # The two blocks are contiguous: minus block first, then plus block.
        signs = [line[0] for line in hunk if line[0] in "+-"]
        self.assertEqual(signs, sorted(signs, reverse=True))

    def test_hunk_headers_carry_deterministic_ids(self):
        diff = semantic_unified_diff(self.data, "reference/x", "candidate/x")
        for removed in self.data["removed"]:
            self.assertIn(f"@@ {element_ident(removed)} @@", diff)
        for added in self.data["added"]:
            self.assertIn(f"@@ {element_ident(added)} @@", diff)

    def test_file_headers_present_only_when_there_are_changes(self):
        diff = semantic_unified_diff(self.data, "reference/x", "candidate/x")
        self.assertEqual(diff[0], "--- reference/x")
        self.assertEqual(diff[1], "+++ candidate/x")

        identical = compare_document_set(self.reference, self.reference)["sbom-build.spdx.json"]
        self.assertEqual(semantic_unified_diff(identical, "reference/x", "candidate/x"), [])


class TestLargeListCompression(unittest.TestCase):
    def package(self, extra_entry: dict | None) -> dict:
        entries = [
            {"type": "DictionaryEntry", "key": f"KEY{i}", "value": f"value-{i}"}
            for i in range(25)
        ]
        if extra_entry:
            entries.append(extra_entry)
        return {
            "type": "software_Package",
            "spdxId": "pkg:0",
            "creationInfo": "_:creationinfo",
            "name": "the-package",
            "build_environment": entries,
        }

    def _document(self, element: dict) -> dict:
        return normalize_document_set(
            {"sbom-build.spdx.json": document([DOC, AGENT, CREATION_INFO, element])}
        )

    def setUp(self):
        reference = self._document(self.package(None))
        candidate = self._document(
            self.package({"type": "DictionaryEntry", "key": "NEW", "value": "x"})
        )
        self.data = compare_document_set(reference, candidate)["sbom-build.spdx.json"]

    def test_changed_element_is_compressed(self):
        diff = "\n".join(semantic_unified_diff(self.data, "reference/x", "candidate/x"))
        self.assertIn("unchanged entries omitted", diff)
        self.assertNotIn("value-0", diff)  # unchanged entries are gone
        self.assertIn('"key": "NEW"', diff)  # the differing entry remains

    def test_small_lists_are_not_compressed(self):
        element = dict(self.package(None), build_environment=[{"key": "only"}])
        reference = self._document(element)
        candidate = self._document(
            dict(element, build_environment=[{"key": "only"}, {"key": "new"}])
        )
        data = compare_document_set(reference, candidate)["sbom-build.spdx.json"]
        diff = "\n".join(semantic_unified_diff(data, "reference/x", "candidate/x"))
        self.assertNotIn("unchanged entries omitted", diff)
        self.assertIn('"key": "new"', diff)

    def test_identical_large_list_leaves_element_unchanged(self):
        """Filtering is display-only: identical elements still match."""
        result = compare_document_set(self._document(self.package(None)), self._document(self.package(None)))
        self.assertEqual(result["sbom-build.spdx.json"]["changed"], [])


if __name__ == "__main__":
    unittest.main()