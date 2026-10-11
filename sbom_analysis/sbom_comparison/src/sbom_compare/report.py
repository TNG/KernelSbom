# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""HTML and JSON report rendering for sbom-compare.

The HTML and CSS live in the `templates/` directory next to this module and
are loaded via `importlib.resources`, so they ship inside the installed
package. The HTML template contains `{{placeholder}}` markers that are filled
with plain string replacement.

The side-by-side diff view aligns the reference and candidate lines of every
hunk with a single batched `git diff` invocation (git's C xdiff is orders of
magnitude faster than anything pure Python on repetitive content), and
highlights changed lines down to the differing words.
"""

from __future__ import annotations

import html
import json
import logging
import re
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from itertools import zip_longest
from importlib.resources import files
from pathlib import Path
from typing import Any

from sbom_compare.load import _Progress, element_ident

logger = logging.getLogger(__name__)

_ELLIPSIS = "⋯"

#: Matches the hunk header of a unified diff: `@@ -12,3 +12,4 @@` (the counts
#: are optional and default to 1).
_GIT_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

#: Above this many diff lines in total, the batched git alignment is logged
#: with its timing, so slow invocations are visible in the progress log.
_LARGE_DIFF_LINES = 10_000

_warned_git_unavailable = False
_warned_hunk_fallback = False

_SENTINEL_PREFIX = "@@SBOM-COMPARE-HUNK-"


def _load_template(name: str) -> str:
    return files("sbom_compare").joinpath("templates", name).read_text(encoding="utf-8")


def _render_template(template: str, **values: str) -> str:
    """Fill `{{placeholder}}` markers with plain string replacement."""
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    return rendered


def _parse_diff_hunks(diff_lines: list[str]) -> tuple[str | None, str | None, list[dict]]:
    """Split semantic diff lines into the file headers and per-element hunks.

    Returns (left_header, right_header, hunks) where each hunk is
    {"header": str, "left": [reference lines], "right": [candidate lines]}
    with the `-`/`+` prefixes stripped.
    """
    left_header: str | None = None
    right_header: str | None = None
    hunks: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    for line in diff_lines:
        if line.startswith("--- "):
            left_header = line[4:]
        elif line.startswith("+++ "):
            right_header = line[4:]
        elif line.startswith("@@ "):
            current = {"header": line, "left": [], "right": []}
            hunks.append(current)
        elif line.startswith("-") and current is not None:
            current["left"].append(line[1:])
        elif line.startswith("+") and current is not None:
            current["right"].append(line[1:])
    return left_header, right_header, hunks


def _highlight_words(left: str, right: str) -> tuple[str, str]:
    """Highlight the differing part of two lines (word-level coloring).

    Trims the common prefix and suffix; only the differing middle gets the
    strong `wdel`/`wadd` highlight. Returns (left_html, right_html).
    """
    limit = min(len(left), len(right))
    prefix = 0
    while prefix < limit and left[prefix] == right[prefix]:
        prefix += 1
    suffix = 0
    while suffix < limit - prefix and left[-1 - suffix] == right[-1 - suffix]:
        suffix += 1

    def side(text: str, css: str) -> str:
        middle_start, middle_end = prefix, len(text) - suffix
        return (
            html.escape(text[:middle_start])
            + f'<span class="{css}">{html.escape(text[middle_start:middle_end])}</span>'
            + html.escape(text[middle_end:])
        )

    return side(left, "wdel"), side(right, "wadd")


def _diff_row(left_line: str, right_line: str) -> str:
    """One side-by-side table row with fine-grained highlighting.

    - equal content on both sides: plain, uncolored cells
    - differing content: del/add cells with word-level highlighting
    - a line only on one side: full del/add cell, blank cell on the other
    """
    if left_line and right_line:
        if left_line == right_line:
            return f"<td>{html.escape(left_line)}</td><td>{html.escape(right_line)}</td>"
        left_html, right_html = _highlight_words(left_line, right_line)
        return f'<td class="del">{left_html}</td><td class="add">{right_html}</td>'
    left_class = "del" if left_line else "blank"
    right_class = "add" if right_line else "blank"
    return (
        f'<td class="{left_class}">{html.escape(left_line)}</td>'
        f'<td class="{right_class}">{html.escape(right_line)}</td>'
    )


def _pairs_from_git_diff(
    diff_lines: list[str], left: list[str], right: list[str]
) -> list[tuple[str, str]]:
    """Turn the unified diff of two full texts back into aligned line pairs.

    Walks the diff hunk headers and `-`/`+` lines, pairing the unchanged
    regions between hunks and index-wise pairing the change runs.
    """
    pairs: list[tuple[str, str]] = []
    left_run: list[str] = []
    right_run: list[str] = []
    left_pos = right_pos = 0  # next unpaired line index on each side

    def flush() -> None:
        nonlocal left_run, right_run, left_pos, right_pos
        if left_run or right_run:
            pairs.extend(zip_longest(left_run, right_run, fillvalue=""))
        left_pos += len(left_run)
        right_pos += len(right_run)
        left_run, right_run = [], []

    for line in diff_lines:
        if line.startswith("@@"):
            match = _GIT_HUNK_RE.match(line)
            if match is None:
                continue
            flush()
            left_number = int(match.group(1))
            left_count = int(match.group(2)) if match.group(2) is not None else 1
            right_number = int(match.group(3))
            right_count = int(match.group(4)) if match.group(4) is not None else 1
            # Zero counts (pure insertions/deletions) point *after* the gap
            # on that side ("N,0" = following line N), so the number itself
            # is the 0-based end of the equal region; otherwise the number
            # is the 1-based first line of the change.
            left_start = left_number if left_count == 0 else left_number - 1
            right_start = right_number if right_count == 0 else right_number - 1
            # The region before this hunk is unchanged on both sides.
            pairs.extend(zip(left[left_pos:left_start], right[right_pos:right_start]))
            left_pos, right_pos = left_start, right_start
        elif line.startswith(("--- ", "+++ ")):
            # git's own file headers, not content lines
            continue
        elif line.startswith("-"):
            left_run.append(line[1:])
        elif line.startswith("+"):
            right_run.append(line[1:])
        # everything else ("diff --git", "index", "\ No newline") needs no handling
    flush()
    pairs.extend(zip(left[left_pos:], right[right_pos:]))
    return pairs


def _git_aligned_pairs_available() -> bool:
    """Whether the git-based alignment can be used in this environment."""
    import shutil

    return shutil.which("git") is not None


def _git_diff_lines(left_lines: list[str], right_lines: list[str]) -> list[str] | None:
    """Run one `git diff --no-index -U0` over two line lists."""
    with tempfile.TemporaryDirectory() as tmp:
        left_path = Path(tmp) / "reference"
        right_path = Path(tmp) / "candidate"
        left_path.write_text("\n".join(left_lines) + "\n", encoding="utf-8")
        right_path.write_text("\n".join(right_lines) + "\n", encoding="utf-8")
        try:
            result = subprocess.run(
                ["git", "diff", "--no-index", "-U0", str(left_path), str(right_path)],
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
    # git exits 0 for no differences and 1 for differences; anything else is trouble
    if result.returncode not in (0, 1):
        return None
    return result.stdout.splitlines()


def _sentinel_stream_valid(pairs: list[tuple[str, str]], hunk_count: int) -> bool:
    """Whether every sentinel appears exactly once, on the left, in order.

    git's xdiff falls back to heuristics on huge, highly repetitive input and
    then no longer matches the sentinel lines one-to-one — the alignment
    would mix up neighboring hunks. Detecting that lets the caller split the
    batch instead of trusting a corrupted alignment.
    """
    expected = 0
    for left_line, right_line in pairs:
        left_is_sentinel = left_line.startswith(_SENTINEL_PREFIX)
        right_is_sentinel = right_line.startswith(_SENTINEL_PREFIX)
        if right_is_sentinel and (not left_is_sentinel or left_line != right_line):
            return False
        if left_is_sentinel:
            index = int(left_line[len(_SENTINEL_PREFIX) :].removesuffix("@@"))
            if index != expected:
                return False
            expected += 1
    return expected == hunk_count


def _split_pairs_at_sentinels(
    pairs: list[tuple[str, str]], hunk_count: int
) -> list[list[tuple[str, str]]]:
    """Split a valid aligned pair stream back into hunks at the sentinel lines."""
    per_hunk: list[list[tuple[str, str]]] = [[] for _ in range(hunk_count)]
    current = 0
    for left_line, right_line in pairs:
        if left_line.startswith(_SENTINEL_PREFIX):
            current = int(left_line[len(_SENTINEL_PREFIX) :].removesuffix("@@"))
            continue
        per_hunk[current].append((left_line, right_line))
    return per_hunk


def _align_hunks(hunks: list[dict]) -> list[list[tuple[str, str]]] | None:
    """Align every hunk's reference/candidate lines with a single `git diff`.

    The hunks' lines are written to two temporary files, separated by unique
    sentinel lines that git can only match one-to-one, so one process spawn
    covers all hunks of a document. On huge repetitive hunks git's heuristic
    diff can miss the sentinel matching, though — the result is validated and
    the batch is bisected until every part aligns cleanly. Hunks that git
    cannot align even alone fall back to index-wise pairing. Returns None
    only if git is unavailable or fails outright.
    """
    if not hunks:
        return []
    sentinels = [f"{_SENTINEL_PREFIX}{index}@@" for index in range(len(hunks))]
    left_lines: list[str] = []
    right_lines: list[str] = []
    for sentinel, hunk in zip(sentinels, hunks):
        left_lines += [sentinel, *hunk["left"]]
        right_lines += [sentinel, *hunk["right"]]
    diff = _git_diff_lines(left_lines, right_lines)
    if diff is None:
        return None
    pairs = _pairs_from_git_diff(diff, left_lines, right_lines)
    if _sentinel_stream_valid(pairs, len(hunks)):
        return _split_pairs_at_sentinels(pairs, len(hunks))
    if len(hunks) == 1:
        global _warned_hunk_fallback
        if not _warned_hunk_fallback:
            _warned_hunk_fallback = True
            logger.warning(
                "git could not align a large repetitive hunk cleanly; "
                "falling back to index-wise line pairing for it"
            )
        return [list(zip_longest(hunks[0]["left"], hunks[0]["right"], fillvalue=""))]
    middle = len(hunks) // 2
    first = _align_hunks(hunks[:middle])
    second = _align_hunks(hunks[middle:])
    if first is None or second is None:
        return None
    return first + second


def render_diff_html(diff_lines: list[str]) -> str:
    """Render the semantic diff as a side-by-side table.

    The reference element is shown on the left and the candidate element on
    the right. Within a hunk the two blocks are aligned with a line-level
    diff, so only the actually changed lines are highlighted; changed lines
    additionally get word-level highlighting, and lines without a counterpart
    on the other side get a blank cell.
    """
    if not diff_lines:
        return '<p class="none">No differences.</p>'
    left_header, right_header, hunks = _parse_diff_hunks(diff_lines)
    total_lines = sum(len(hunk["left"]) + len(hunk["right"]) for hunk in hunks)
    logger.info(
        "rendering side-by-side diff [%s]: %d hunks, %d lines",
        left_header or "unknown document",
        len(hunks),
        total_lines,
    )
    start = time.monotonic()
    alignments = _align_hunks(hunks)
    if alignments is None:
        global _warned_git_unavailable
        if not _warned_git_unavailable:
            _warned_git_unavailable = True
            logger.warning(
                "git is not available (or failed); falling back to index-wise "
                "line pairing, so insertions and deletions may misalign "
                "the following lines of a hunk"
            )
        alignments = [
            list(zip_longest(hunk["left"], hunk["right"], fillvalue=""))
            for hunk in hunks
        ]
    elif total_lines > _LARGE_DIFF_LINES:
        logger.info("aligned %d lines with git diff in %.1fs", total_lines, time.monotonic() - start)

    step = _Progress(f"rendering diff [{left_header or 'unknown document'}]", total_lines)
    rows = [
        "<tr><th>{}</th><th>{}</th></tr>".format(
            html.escape(left_header or "reference"),
            html.escape(right_header or "candidate"),
        )
    ]
    lines_done = 0
    for index, hunk in enumerate(hunks):
        if index:
            rows.append(f'<tr class="gap"><td colspan="2">{_ELLIPSIS}</td></tr>')
        rows.append(
            f'<tr class="hunk"><td colspan="2">{html.escape(hunk["header"])}</td></tr>'
        )
        for left_line, right_line in alignments[index]:
            rows.append(f"<tr>{_diff_row(left_line, right_line)}</tr>")
            lines_done += 1
            if lines_done % 1000 == 0:
                step.update(lines_done)
    step.finish()
    return '<table class="diff">' + "".join(rows) + "</table>"


def _summary_rows(documents: dict[str, dict]) -> str:
    rows = []
    for name, data in documents.items():
        counts = {kind: len(data[kind]) for kind in ("added", "removed", "changed")}
        rows.append(
            f"<tr><td>{html.escape(name)}</td>"
            f"<td class='num'>{counts['added']}</td>"
            f"<td class='num'>{counts['removed']}</td>"
            f"<td class='num'>{counts['changed']}</td></tr>"
        )
    return (
        "<table><tr><th>Document</th><th>Added</th><th>Removed</th><th>Changed</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def render_html(report: dict[str, Any]) -> str:
    """Render the full self-contained HTML report."""
    documents = report["documents"]
    has_changes = any(
        data["added"] or data["removed"] or data["changed"] for data in documents.values()
    )
    verdict_class = "differ" if has_changes else "identical"
    verdict_text = "Differences found" if has_changes else "Semantically identical"

    sections = []
    for name, data in documents.items():
        sections.append(f"<h2>{html.escape(name)}</h2>")
        sections.append(_summary_rows({name: data}))
        sections.append(render_diff_html(data["diff"]))

    return _render_template(
        _load_template("report.html.template"),
        css=_load_template("report.css"),
        verdict_class=verdict_class,
        verdict_text=verdict_text,
        comparison_dir=html.escape(report["comparison_dir"]),
        generated=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        summary_table=_summary_rows(documents),
        sections="".join(sections),
    )


def _summary_entries(elements: Any) -> list[dict]:
    """id/type summaries of changed elements for the JSON report, sorted by id.

    Accepts plain elements (added/removed) and (reference, candidate) pairs
    (changed); for pairs the reference side carries id and type.
    """
    summaries = []
    for entry in elements:
        element = entry[0] if isinstance(entry, tuple) else entry
        summaries.append({"id": element_ident(element), "type": element.get("type", "unknown")})
    return sorted(summaries, key=lambda summary: summary["id"])


def render_json(report: dict[str, Any]) -> str:
    """Render the machine-readable JSON report."""
    json_report = {
        "comparison_dir": report["comparison_dir"],
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "documents": {
            name: {
                "added": _summary_entries(data["added"]),
                "removed": _summary_entries(data["removed"]),
                "changed": _summary_entries(data["changed"]),
                "diff": data["diff"],
            }
            for name, data in report["documents"].items()
        },
    }
    return json.dumps(json_report, indent=2, ensure_ascii=False) + "\n"


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
