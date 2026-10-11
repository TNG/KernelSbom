# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""Load and normalize SPDX SBOM documents for comparison.

The sbom generator assigns element ids (`spdxId`) by traversal order, so the
same object can end up with different ids in two builds. This module rewrites
every `spdxId` and every reference to a deterministic identifier derived from
the element's own content, so unchanged elements serialize identically in the
reference and the candidate variant.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DOCUMENT_FILES = (
    "sbom-output.spdx.json",
    "sbom-build.spdx.json",
    "sbom-source.spdx.json",
)

#: The id of a relationship depends on the ids of its endpoints, and documents
#: reference elements of sibling documents (e.g. the build document references
#: output-document files). Resolving this is a fixed-point computation.
MAX_RESOLUTION_PASSES = 10

_REF_LIKE_RE = re.compile(r"[a-z]+:\d+")


class SbomCompareError(Exception):
    """Raised when input documents cannot be loaded or compared."""


class _Progress:
    """Throttled progress logging for long-running loops.

    Emits an INFO log line at most every `min_interval` seconds, so loops
    over hundreds of thousands of elements produce meaningful progress
    output without flooding the log.
    """

    def __init__(self, description: str, total: int, min_interval: float = 2.0) -> None:
        self._description = description
        self._total = total
        self._min_interval = min_interval
        self._start = time.monotonic()
        self._last = self._start

    def update(self, done: int) -> None:
        now = time.monotonic()
        if now - self._last < self._min_interval:
            return
        self._last = now
        percent = 100.0 * done / self._total if self._total else 100.0
        logger.info(
            "%s: %d/%d (%.0f%%), %.1fs elapsed",
            self._description,
            done,
            self._total,
            percent,
            now - self._start,
        )

    def finish(self) -> None:
        logger.info(
            "%s: done, %d items in %.1fs",
            self._description,
            self._total,
            time.monotonic() - self._start,
        )


def load_document(path: Path) -> dict:
    """Load one spdx.json document."""
    logger.info("loading %s", path)
    start = time.monotonic()
    try:
        with open(path, encoding="utf-8") as file:
            document = json.load(file)
    except FileNotFoundError as exc:
        raise SbomCompareError(f"missing SBOM document: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SbomCompareError(f"invalid JSON in {path}: {exc}") from exc
    logger.info(
        "loaded %s: %d graph elements in %.1fs",
        path.name,
        len(document.get("@graph", [])),
        time.monotonic() - start,
    )
    return document


def _content_hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _iter_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _iter_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_strings(item)


def _is_ref_like(value: str) -> bool:
    """True for strings that are generator-assigned ids or blank-node refs."""
    return bool(_REF_LIKE_RE.fullmatch(value)) or value.startswith("_:")


def _element_identifier(element: dict) -> str | None:
    """The original id of an element: `spdxId`, or `@id` for blank nodes."""
    return element.get("spdxId") or element.get("@id")


def element_ident(element: dict) -> str:
    """The id of a normalized element; content hash fallback for id-less ones."""
    identifier = _element_identifier(element)
    return identifier if identifier is not None else _canonical(element)


def _base_identity(element: dict) -> str | None:
    """Human-readable identity key for types that do not depend on references."""
    etype = element.get("type")
    if etype == "software_File":
        return f"file:{element.get('software_fileKind', 'file')}:{element.get('name', '')}"
    if etype == "simplelicensing_LicenseExpression":
        return f"license:{element.get('simplelicensing_licenseExpression', '')}"
    if etype == "build_Build":
        return f"build:{_content_hash(element.get('comment', ''))}"
    if etype == "software_Package":
        return f"package:{element.get('name', '')}"
    if etype == "SoftwareAgent":
        return f"agent:{element.get('name', '')}"
    if etype == "software_Sbom":
        return f"sbom:{element.get('name', '')}"
    if etype == "SpdxDocument":
        return "spdx-document"
    return None


class _IdResolver:
    """Fixed-point computation of deterministic ids for a set of documents."""

    def __init__(self, documents: dict[str, dict]) -> None:
        self.graphs = {name: doc.get("@graph", []) for name, doc in documents.items()}
        self.ids: dict[str, dict[str, str]] = {name: {} for name in documents}
        # All deterministic ids assigned so far, maintained incrementally so
        # _unique() stays O(1) per element instead of rescanning all ids.
        self._used: set[str] = set()
        self.pending: dict[str, list[dict]] = {
            name: [e for e in graph if isinstance(e, dict) and _element_identifier(e) is not None]
            for name, graph in self.graphs.items()
        }

    def resolve(self) -> dict[str, dict[str, str]]:
        """Run the fixed-point computation, returns {doc_name: {orig_id: det_id}}."""
        total = sum(len(elements) for elements in self.pending.values())
        logger.info(
            "resolving deterministic ids: %d elements in %d document(s)",
            total,
            len(self.ids),
        )
        still_pending_total = total
        for pass_number in range(1, MAX_RESOLUTION_PASSES + 1):
            if not still_pending_total:
                break
            # Round 1 resolves every element whose identity is self-contained
            # (files, packages, ...). Later rounds resolve the remainder:
            # elements (mostly Relationships) whose deterministic id is
            # derived from the resolved ids of the elements they reference.
            label = "id resolution" if pass_number == 1 else f"id resolution round {pass_number}"
            if pass_number > 1:
                logger.info(
                    "%s: %d elements depend on ids that were not yet resolved",
                    label,
                    still_pending_total,
                )
            resolved_in_pass = 0
            for name in self.ids:
                lookup = self._lookup_for(name)
                still_pending = []
                pending = self.pending[name]
                step = _Progress(f"{label} [{name}]", len(pending))
                for index, element in enumerate(pending):
                    det = self._derive_id(element, lookup)
                    if det is None:
                        still_pending.append(element)
                        continue
                    det = self._unique(det)
                    self.ids[name][_element_identifier(element)] = det
                    resolved_in_pass += 1
                    if index % 1000 == 0:
                        step.update(index)
                step.finish()
                self.pending[name] = still_pending
            still_pending_total = sum(len(elements) for elements in self.pending.values())
            logger.info(
                "%s: %d ids resolved, %d elements still pending",
                label,
                resolved_in_pass,
                still_pending_total,
            )
            if not resolved_in_pass:
                break
        if still_pending_total:
            logger.warning(
                "%d elements could not be resolved within %d rounds; "
                "falling back to pure content hashes (may show up as spurious changes)",
                still_pending_total,
                MAX_RESOLUTION_PASSES,
            )
        # Anything that could not be resolved (e.g. reference cycles) falls back
        # to a pure content hash. The result may differ between the reference
        # and candidate variant in that case, which would show up as a change.
        for name in self.ids:
            for element in self.pending[name]:
                self.ids[name][_element_identifier(element)] = self._unique(
                    f"{element.get('type', 'unknown')}:{_content_hash(element)}"
                )
        return self.ids

    def _lookup_for(self, name: str) -> Callable[[str], str | None]:
        """Resolve a reference against this document first, then sibling docs."""
        own = self.ids[name]
        others = {
            orig: det
            for other_name, mapping in self.ids.items()
            if other_name != name
            for orig, det in mapping.items()
        }

        def lookup(ref: str) -> str | None:
            if ref in own:
                return own[ref]
            return others.get(ref)

        return lookup

    def resolver_for(self, name: str) -> Callable[[str], str]:
        """Total resolver for the rewriting pass: unknown refs pass through."""
        lookup = self._lookup_for(name)

        def resolve(value: str) -> str:
            return lookup(value) or value

        return resolve

    def _unique(self, det: str) -> str:
        """Disambiguate `det` against every id assigned so far (incrementally tracked)."""
        if det not in self._used:
            self._used.add(det)
            return det
        counter = 2
        while f"{det}~{counter}" in self._used:
            counter += 1
        det = f"{det}~{counter}"
        self._used.add(det)
        return det

    def _derive_id(self, element: dict, lookup: Callable[[str], str | None]) -> str | None:
        """Deterministic id for the element, or None if references are unresolved.

        `lookup` resolves references against this document's ids first, then
        against the ids of the sibling documents.
        """
        own_id = _element_identifier(element)
        etype = element.get("type")

        if own_id.startswith("_:"):
            # Blank nodes keep their name; it is shared and stable.
            return own_id

        if etype == "Relationship":
            refs = [element.get("from", ""), *(element.get("to") or [])]
            if any(_is_ref_like(r) and lookup(r) is None for r in refs):
                return None
            resolved_from = lookup(refs[0]) or refs[0]
            # The identity deliberately ignores the `to` targets: a
            # relationship that gains or loses referenced elements (files
            # added to a directory, ...) is a *changed* element, not an
            # unrelated removed + added pair. Multiple relationships that
            # share type and source are disambiguated in document order.
            return f"rel:{_content_hash([element.get('relationshipType'), resolved_from])}"

        base = _base_identity(element)
        if base is not None:
            return base

        # Unknown element type: derive from content, but only once all of its
        # references are resolvable (otherwise the hash is not stable).
        unresolved = [
            s
            for s in _iter_strings(element)
            if s != own_id and _is_ref_like(s) and not s.startswith("_:") and lookup(s) is None
        ]
        if unresolved:
            return None
        content = {k: v for k, v in element.items() if k not in ("spdxId", "@id")}
        return f"{etype}:{_content_hash(content)}"


def _rewrite(element: Any, resolve: Callable[[str], str]) -> Any:
    """Deeply rewrite every string that resolves to a deterministic id."""
    if isinstance(element, str):
        return resolve(element)
    if isinstance(element, list):
        return [_rewrite(item, resolve) for item in element]
    if isinstance(element, dict):
        return {key: _rewrite(value, resolve) for key, value in element.items()}
    return element


def normalize_document_set(documents: dict[str, dict]) -> dict[str, dict]:
    """Rewrite all spdxIds and references of one build's documents in place-free style.

    `documents` maps document file name to loaded document. Documents may
    reference elements of sibling documents (by their generator-assigned ids),
    so ids are resolved across the whole set.

    Returns a new mapping of document file name to a copied document in which
    every id and reference is a deterministic identifier.
    """
    resolver = _IdResolver(documents)
    resolver.resolve()

    normalized: dict[str, dict] = {}
    for name, document in documents.items():
        resolve = resolver.resolver_for(name)
        graph = document.get("@graph", [])
        step = _Progress(f"rewriting ids [{name}]", len(graph))
        new_graph = []
        for index, element in enumerate(graph):
            new_graph.append(_rewrite(element, resolve))
            if index % 1000 == 0:
                step.update(index)
        step.finish()
        new_document = dict(document)
        new_document["@graph"] = new_graph
        normalized[name] = new_document
    return normalized


def _canonical(element: dict) -> str:
    return json.dumps(element, sort_keys=True, ensure_ascii=False)


def compare_document_set(
    reference: dict[str, dict],
    candidate: dict[str, dict],
) -> dict[str, dict]:
    """Filter unchanged elements and classify the remaining changes.

    `reference` holds the SBOM documents of the trusted baseline build,
    `candidate` the documents of the build under test. Returns
    {doc_name: {"added", "removed", "changed"}} where `added` and `removed`
    are the changed elements of the respective variant in document order,
    and `changed` is a list of (reference_element, candidate_element) pairs
    in document order — the input for the semantic diff.
    """
    result: dict[str, dict] = {}
    for name in reference.keys() & candidate.keys():
        reference_graph = reference[name].get("@graph", [])
        candidate_graph = candidate[name].get("@graph", [])
        logger.info(
            "comparing %s: %d reference elements, %d candidate elements",
            name,
            len(reference_graph),
            len(candidate_graph),
        )

        reference_by_id = {element_ident(element): element for element in reference_graph}
        candidate_by_id = {element_ident(element): element for element in candidate_graph}

        added_ids = candidate_by_id.keys() - reference_by_id.keys()
        removed_ids = reference_by_id.keys() - candidate_by_id.keys()
        step = _Progress(f"finding changed elements [{name}]", len(reference_by_id))
        changed_ids: set[str] = set()
        for index, (key, reference_element) in enumerate(reference_by_id.items()):
            candidate_element = candidate_by_id.get(key)
            if candidate_element is not None and _canonical(reference_element) != _canonical(
                candidate_element
            ):
                changed_ids.add(key)
            if index % 1000 == 0:
                step.update(index)
        step.finish()

        result[name] = {
            "added": [
                element for element in candidate_graph if element_ident(element) in added_ids
            ],
            "removed": [
                element for element in reference_graph if element_ident(element) in removed_ids
            ],
            "changed": [
                (element, candidate_by_id[element_ident(element)])
                for element in reference_graph
                if element_ident(element) in changed_ids
            ],
        }
        logger.info(
            "compared %s: %d added, %d removed, %d changed",
            name,
            len(added_ids),
            len(removed_ids),
            len(changed_ids),
        )
    return result