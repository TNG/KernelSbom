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
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

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


def load_document(path: Path) -> dict:
    """Load one spdx.json document."""
    try:
        with open(path, encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError as exc:
        raise SbomCompareError(f"missing SBOM document: {path}") from exc
    except json.JSONDecodeError as exc:
        raise SbomCompareError(f"invalid JSON in {path}: {exc}") from exc


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
        self.orig_ids = {
            name: {
                ident
                for element in graph
                if (ident := _element_identifier(element)) is not None
            }
            for name, graph in self.graphs.items()
        }
        self.ids: dict[str, dict[str, str]] = {name: {} for name in documents}
        self.pending: dict[str, list[dict]] = {
            name: [e for e in graph if isinstance(e, dict) and _element_identifier(e) is not None]
            for name, graph in self.graphs.items()
        }

    def resolve(self) -> dict[str, dict[str, str]]:
        """Run the fixed-point computation, returns {doc_name: {orig_id: det_id}}."""
        for _ in range(MAX_RESOLUTION_PASSES):
            progress = False
            for name in self.ids:
                external = {
                    orig: det
                    for other_name, mapping in self.ids.items()
                    if other_name != name
                    for orig, det in mapping.items()
                }
                still_pending = []
                for element in self.pending[name]:
                    det = self._derive_id(name, element, external)
                    if det is None:
                        still_pending.append(element)
                        continue
                    det = self._unique(det)
                    self.ids[name][self._element_identifier_of(element)] = det
                    progress = True
                self.pending[name] = still_pending
            if not progress:
                break
        # Anything that could not be resolved (e.g. reference cycles) falls back
        # to a pure content hash. The result may differ between the reference
        # and candidate variant in that case, which would show up as a change.
        for name in self.ids:
            for element in self.pending[name]:
                ident = self._element_identifier_of(element)
                self.ids[name][ident] = self._unique(f"{element.get('type', 'unknown')}:{_content_hash(element)}")
        return self.ids

    @staticmethod
    def _element_identifier_of(element: dict) -> str:
        return element["spdxId"] if "spdxId" in element else element["@id"]

    def _unique(self, det: str) -> str:
        used = {d for mapping in self.ids.values() for d in mapping.values()}
        if det not in used:
            return det
        counter = 2
        while f"{det}~{counter}" in used:
            counter += 1
        return f"{det}~{counter}"

    def _known_ids(self, name: str, external: dict[str, str]) -> dict[str, str]:
        return {**external, **self.ids[name]}

    def _derive_id(self, name: str, element: dict, external: dict[str, str]) -> str | None:
        """Deterministic id for the element, or None if references are unresolved."""
        own_id = self._element_identifier_of(element)
        known = self._known_ids(name, external)
        etype = element.get("type")

        if own_id.startswith("_:"):
            # Blank nodes keep their name; it is shared and stable.
            return own_id

        if etype == "Relationship":
            refs = [element.get("from", ""), *(element.get("to") or [])]
            unresolved = [r for r in refs if _is_ref_like(r) and r not in known]
            if unresolved:
                return None
            resolved_from = known.get(refs[0], refs[0])
            resolved_to = sorted(known.get(r, r) for r in refs[1:])
            return f"rel:{_content_hash([element.get('relationshipType'), resolved_from, resolved_to])}"

        base = _base_identity(element)
        if base is not None:
            return base

        # Unknown element type: derive from content, but only once all of its
        # references are resolvable (otherwise the hash is not stable).
        unresolved = [
            s
            for s in _iter_strings(element)
            if s != own_id and _is_ref_like(s) and not s.startswith("_:") and s not in known
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
    ids_per_doc = _IdResolver(documents).resolve()

    def make_resolver(name: str) -> Callable[[str], str]:
        own = ids_per_doc[name]
        others = [ids_per_doc[other] for other in ids_per_doc if other != name]

        def resolve(value: str) -> str:
            if value in own:
                return own[value]
            for mapping in others:
                if value in mapping:
                    return mapping[value]
            return value

        return resolve

    normalized: dict[str, dict] = {}
    for name, document in documents.items():
        resolve = make_resolver(name)
        new_document = dict(document)
        new_document["@graph"] = [_rewrite(element, resolve) for element in document.get("@graph", [])]
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
    {doc_name: {"added", "removed", "changed", "reference_text",
    "candidate_text"}} where added/removed/changed are lists of
    {"id", "type"} entries and *_text are the serialized, filtered documents
    ready for diffing.
    """
    result: dict[str, dict] = {}
    for name in reference.keys() & candidate.keys():
        reference_graph = reference[name].get("@graph", [])
        candidate_graph = candidate[name].get("@graph", [])

        def ident(element: dict) -> str:
            identifier = _element_identifier(element)
            return identifier if identifier is not None else _canonical(element)

        reference_by_id = {ident(element): element for element in reference_graph}
        candidate_by_id = {ident(element): element for element in candidate_graph}

        added_ids = candidate_by_id.keys() - reference_by_id.keys()
        removed_ids = reference_by_id.keys() - candidate_by_id.keys()
        changed_ids = {
            key
            for key in reference_by_id.keys() & candidate_by_id.keys()
            if _canonical(reference_by_id[key]) != _canonical(candidate_by_id[key])
        }

        def summary(ids, elements_by_id):
            return sorted(
                ({"id": key, "type": elements_by_id[key].get("type", "unknown")} for key in ids),
                key=lambda entry: entry["id"],
            )

        filtered_reference = dict(reference[name])
        filtered_reference["@graph"] = [
            element for element in reference_graph if ident(element) in removed_ids | changed_ids
        ]
        filtered_candidate = dict(candidate[name])
        filtered_candidate["@graph"] = [
            element for element in candidate_graph if ident(element) in added_ids | changed_ids
        ]

        result[name] = {
            "added": summary(added_ids, candidate_by_id),
            "removed": summary(removed_ids, reference_by_id),
            "changed": summary(changed_ids, reference_by_id),
            "reference_text": json.dumps(filtered_reference, indent=2, ensure_ascii=False) + "\n",
            "candidate_text": json.dumps(filtered_candidate, indent=2, ensure_ascii=False) + "\n",
        }
    return result