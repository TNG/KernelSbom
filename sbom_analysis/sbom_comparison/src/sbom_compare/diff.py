# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""Git-style unified diff over normalized SBOM documents."""

from __future__ import annotations

import difflib


def unified_diff(
    reference_text: str,
    candidate_text: str,
    fromfile: str,
    tofile: str,
    context: int = 3,
) -> list[str]:
    """One unified diff of the two normalized document texts.

    Unchanged regions are omitted by the diff mechanism itself; only hunks
    containing actual changes are returned, with `context` lines of context.
    """
    return list(
        difflib.unified_diff(
            reference_text.splitlines(),
            candidate_text.splitlines(),
            fromfile=fromfile,
            tofile=tofile,
            n=context,
            lineterm="",
        )
    )