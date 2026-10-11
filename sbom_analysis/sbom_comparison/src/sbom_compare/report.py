# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""HTML and JSON report rendering for sbom-compare.

The HTML and CSS live in the `templates/` directory next to this module and
are loaded via `importlib.resources`, so they ship inside the installed
package. The HTML template contains `{{placeholder}}` markers that are filled
with plain string replacement.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Any

_ELLIPSIS = "⋯"


def _load_template(name: str) -> str:
    return files("sbom_compare").joinpath("templates", name).read_text(encoding="utf-8")


def _render_template(template: str, **values: str) -> str:
    """Fill `{{placeholder}}` markers with plain string replacement."""
    rendered = template
    for key, value in values.items():
        rendered = rendered.replace("{{" + key + "}}", value)
    return rendered


def _diff_line_class(line: str) -> str:
    if line.startswith("@@"):
        return "hunk"
    if line.startswith(("+++", "---")):
        return "filehdr"
    if line.startswith("+"):
        return "add"
    if line.startswith("-"):
        return "del"
    return "ellip" if _ELLIPSIS in line else ""


def render_diff_html(diff_lines: list[str]) -> str:
    """Render unified-diff lines as colored HTML."""
    if not diff_lines:
        return '<p class="none">No differences.</p>'
    out = ['<pre class="diff">']
    previous_class: str | None = None
    for line in diff_lines:
        css = _diff_line_class(line)
        if css:
            gap = (
                '<span class="ellip">⋯</span>\n'
                if css in ("hunk", "filehdr") and previous_class not in (None, "hunk", "filehdr")
                else ""
            )
            out.append(gap + f'<span class="{css}">{html.escape(line)}</span>\n')
            previous_class = css
        else:
            out.append(html.escape(line) + "\n")
    out.append("</pre>")
    return "".join(out)


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


def render_json(report: dict[str, Any]) -> str:
    """Render the machine-readable JSON report."""
    json_report = {
        "comparison_dir": report["comparison_dir"],
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "documents": {
            name: {
                "added": data["added"],
                "removed": data["removed"],
                "changed": data["changed"],
                "diff": data["diff"],
            }
            for name, data in report["documents"].items()
        },
    }
    return json.dumps(json_report, indent=2, ensure_ascii=False) + "\n"


def write_report(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")