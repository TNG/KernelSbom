# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""Git-style unified diff over normalized SBOM documents.

The comparison has already classified every element as added, removed, or
changed. The diff is therefore assembled directly from that classification
instead of running a generic longest-common-subsequence diff: the output is
fully determined by the element pairing, and a generic SequenceMatcher is far
too slow on documents with hundreds of thousands of lines.
"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from sbom_compare.load import _canonical, element_ident

#: List fields longer than this many entries are compressed in the diff view
#: of changed elements: entries that are identical on both sides are omitted
#: and replaced by a marker (display only, the classification is unaffected).
_LARGE_LIST_ENTRIES = 20


def _prefixed(prefix: str, element: dict) -> list[str]:
    """One element pretty-printed, every line prefixed with `-` or `+`."""
    text = json.dumps(element, indent=2, ensure_ascii=False)
    return [prefix + line for line in text.splitlines()]


def _compress_lists(reference_element: dict, candidate_element: dict) -> tuple[dict, dict]:
    """Drop identical entries from large list fields of a changed element pair.

    A changed element can be huge because of long list fields that barely
    differ (the build environment, relationship `to` lists, document
    imports, ...). For every field that is a list longer than
    `_LARGE_LIST_ENTRIES` on both sides, entries whose canonical form appears
    in both lists (same count) are omitted and replaced by a marker string.

    Returns (shrunken_reference, shrunken_candidate).
    """
    ref_shrunk = dict(reference_element)
    cand_shrunk = dict(candidate_element)
    for key, ref_value in ref_shrunk.items():
        cand_value = cand_shrunk.get(key)
        if (
            not isinstance(ref_value, list)
            or not isinstance(cand_value, list)
            or len(ref_value) <= _LARGE_LIST_ENTRIES
            or len(cand_value) <= _LARGE_LIST_ENTRIES
        ):
            continue
        ref_counts = Counter(_canonical(entry) for entry in ref_value)
        cand_counts = Counter(_canonical(entry) for entry in cand_value)
        common = ref_counts & cand_counts  # multiset intersection
        if not common:
            continue

        def remaining(values: list, counts: Counter) -> list:
            kept = []
            local = counts.copy()
            for entry in values:
                canonical = _canonical(entry)
                if local.get(canonical):
                    local[canonical] -= 1
                    continue
                kept.append(entry)
            return kept

        marker = f"⋯ {sum(common.values())} unchanged entries omitted"
        ref_shrunk[key] = [*remaining(ref_value, common), marker]
        cand_shrunk[key] = [*remaining(cand_value, common), marker]
    return ref_shrunk, cand_shrunk


def semantic_unified_diff(data: dict[str, Any], fromfile: str, tofile: str) -> list[str]:
    """Git-style unified diff assembled from the already-classified elements.

    `data` is one entry of `compare_document_set`'s result: the removed and
    added elements, and the changed (reference, candidate) pairs.

    Each element becomes one hunk, headed by its deterministic id:
    removed elements render as `-` lines, added elements as `+` lines, and
    changed elements as a `-`/`+` pair in a single hunk (like a modified line
    in git). Returns [] when there are no differences.
    """
    hunks: list[list[str]] = []
    for element in data["removed"]:
        hunks.append([f"@@ {element_ident(element)} @@"] + _prefixed("-", element))
    for reference_element, candidate_element in data["changed"]:
        # Large list fields (build environment, `to` lists, ...) would
        # dump hundreds of unchanged entries; keep only the differing ones.
        reference_shrunk, candidate_shrunk = _compress_lists(
            reference_element, candidate_element
        )
        hunks.append(
            [f"@@ {element_ident(reference_element)} @@"]
            + _prefixed("-", reference_shrunk)
            + _prefixed("+", candidate_shrunk)
        )
    for element in data["added"]:
        hunks.append([f"@@ {element_ident(element)} @@"] + _prefixed("+", element))

    if not hunks:
        return []
    lines = [f"--- {fromfile}", f"+++ {tofile}"]
    for hunk in hunks:
        lines.extend(hunk)
    return lines