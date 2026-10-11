# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""Unit tests for the HTML report rendering."""

import unittest
from unittest import mock

import sbom_compare.report as report
from sbom_compare.report import (
    _align_hunks,
    _git_aligned_pairs_available,
    _sentinel_stream_valid,
    render_diff_html,
)

HEADER = [
    "--- reference/sbom-build.spdx.json",
    "+++ candidate/sbom-build.spdx.json",
]

HAS_GIT = _git_aligned_pairs_available()


def _git_aligned_pairs(left: list[str], right: list[str]) -> list[tuple[str, str]]:
    """Align a single pair of line lists via the batched git alignment."""
    return _align_hunks([{"header": "", "left": left, "right": right}])[0]


class TestRenderDiffHtml(unittest.TestCase):
    def test_no_differences(self):
        self.assertEqual(render_diff_html([]), '<p class="none">No differences.</p>')

    @unittest.skipUnless(HAS_GIT, "git is not available")
    def test_column_headers(self):
        out = render_diff_html([*HEADER, "@@ _:creationinfo @@", '-  "a": 1', '+  "a": 2'])
        self.assertIn("<th>reference/sbom-build.spdx.json</th>", out)
        self.assertIn("<th>candidate/sbom-build.spdx.json</th>", out)

    @unittest.skipUnless(HAS_GIT, "git is not available")
    def test_equal_lines_are_plain(self):
        equal_line = '  "type": "software_File",'
        escaped_line = '  &quot;type&quot;: &quot;software_File&quot;,'
        out = render_diff_html(
            [*HEADER, "@@ file:file:a.c @@", f"-{equal_line}", f"+{equal_line}"]
        )
        self.assertIn(f"<td>{escaped_line}</td>", out)
        self.assertNotIn('class="del"', out)
        self.assertNotIn('class="add"', out)

    @unittest.skipUnless(HAS_GIT, "git is not available")
    def test_differing_lines_are_word_highlighted(self):
        out = render_diff_html(
            [
                *HEADER,
                "@@ _:creationinfo @@",
                '-  "created": "2026-10-11T04:52Z"',
                '+  "created": "2026-10-11T15:36Z"',
            ]
        )
        # Only the changed middle of the line carries the strong highlight.
        self.assertIn('<span class="wdel">04:52</span>', out)
        self.assertIn('<span class="wadd">15:36</span>', out)

    @unittest.skipUnless(HAS_GIT, "git is not available")
    def test_one_sided_lines_get_full_cell_and_blank(self):
        out = render_diff_html([*HEADER, "@@ file:file:b.c @@", '-  "name": "init/main.c"'])
        self.assertIn('class="del"', out)
        self.assertIn('class="blank"', out)
        self.assertNotIn('class="add"', out)

    @unittest.skipUnless(HAS_GIT, "git is not available")
    def test_inserted_line_does_not_shift_alignment(self):
        """An inserted line must not flag the following lines as changed."""
        out = render_diff_html(
            [
                *HEADER,
                "@@ rel:the-list @@",
                '-  "file:file:fs/efivars/inode.o",',
                '-  "file:file:fs/efivars/super.o",',
                '+  "file:file:fs/efivars/efivars.mod",',
                '+  "file:file:fs/efivars/inode.o",',
                '+  "file:file:fs/efivars/super.o",',
            ]
        )
        # Only the inserted line is green; the others are plain.
        self.assertIn('class="add"', out)
        self.assertNotIn('class="del"', out)
        self.assertIn("<td>  &quot;file:file:fs/efivars/inode.o&quot;,</td>", out)


@unittest.skipUnless(HAS_GIT, "git is not available")
class TestGitAlignedPairs(unittest.TestCase):
    def test_insertion(self):
        pairs = _git_aligned_pairs(["a", "c"], ["a", "b", "c"])
        self.assertEqual(pairs, [("a", "a"), ("", "b"), ("c", "c")])

    def test_deletion(self):
        pairs = _git_aligned_pairs(["a", "b", "c"], ["a", "c"])
        self.assertEqual(pairs, [("a", "a"), ("b", ""), ("c", "c")])

    def test_replace_pairs_index_wise(self):
        pairs = _git_aligned_pairs(['  "x": 1,'], ['  "x": 2,'])
        self.assertEqual(pairs, [('  "x": 1,', '  "x": 2,')])

    def test_identical(self):
        pairs = _git_aligned_pairs(["a", "b"], ["a", "b"])
        self.assertEqual(pairs, [("a", "a"), ("b", "b")])

    def test_change_at_start(self):
        """git reports changes at the very start with a `0` position."""
        pairs = _git_aligned_pairs(["a", "b"], ["x", "a", "b"])
        self.assertEqual(pairs, [("", "x"), ("a", "a"), ("b", "b")])

    def test_multiple_hunks_in_one_batch(self):
        """Several hunks in one file stay separated by their sentinels."""
        left = ["a", "b"] * 50 + ["x"] * 3
        right = ["a", "b"] * 50 + ["y"] * 3
        pairs = _git_aligned_pairs(left, right)
        # git reports one replace hunk; replace runs pair index-wise.
        self.assertEqual(pairs, [("a", "a"), ("b", "b")] * 50 + [("x", "y")] * 3)

    def test_insertion_between_repeated_lines(self):
        """The case where difflib is slow must align correctly via git."""
        left = ["{"] * 3 + ['"a.c"'] + ["}"] * 3
        right = ["{"] * 3 + ['"a.c"', '"b.mod"', '"c.o"'] + ["}"] * 3
        pairs = _git_aligned_pairs(left, right)
        # Nothing is deleted, nothing is duplicated: each right line gets
        # exactly one row, and the unique line aligns with itself. Where the
        # inserted lines land among the repeated braces is up to the diff.
        self.assertEqual(len(pairs), len(right))
        self.assertIn(('"a.c"', '"a.c"'), pairs)
        self.assertIn(("", '"b.mod"'), pairs)
        self.assertIn(("", '"c.o"'), pairs)
        self.assertEqual(pairs.count(("{", "{")), 3)
        self.assertEqual(pairs.count(("}", "}")), 3)


class TestSentinelValidation(unittest.TestCase):
    S0 = report._SENTINEL_PREFIX + "0@@"
    S1 = report._SENTINEL_PREFIX + "1@@"

    def test_valid_stream(self):
        # (sentinel, sentinel) pairs are the normal unchanged-region case.
        self.assertTrue(_sentinel_stream_valid([(self.S0, self.S0), ("a", "a"), (self.S1, self.S1), ("b", "")], 2))

    def test_right_sentinel_without_left_is_invalid(self):
        self.assertFalse(_sentinel_stream_valid([("", self.S1), ("a", "a")], 2))

    def test_wrong_sentinel_order_is_invalid(self):
        self.assertFalse(_sentinel_stream_valid([(self.S1, self.S1), (self.S0, self.S0)], 2))

    def test_missing_sentinel_is_invalid(self):
        self.assertFalse(_sentinel_stream_valid([(self.S0, self.S0), ("a", "a")], 2))


@unittest.skipUnless(HAS_GIT, "git is not available")
class TestBatchBisection(unittest.TestCase):
    """A corrupted batch alignment must be repaired by splitting the batch."""

    HUNKS = [
        {"header": "@@ a @@", "left": ["x"], "right": ["y"]},
        {"header": "@@ b @@", "left": ["p"], "right": ["q"]},
    ]

    def test_bisect_recovers_clean_alignment(self):
        real = report._pairs_from_git_diff

        def corrupt(diff_lines, left, right):
            sentinels = sum(1 for line in left if line.startswith(report._SENTINEL_PREFIX))
            return [] if sentinels > 1 else real(diff_lines, left, right)

        with mock.patch.object(report, "_pairs_from_git_diff", side_effect=corrupt):
            aligned = report._align_hunks(self.HUNKS)
        self.assertEqual(aligned, [[("x", "y")], [("p", "q")]])

    def test_single_hunk_failure_falls_back_index_wise(self):
        with mock.patch.object(report, "_pairs_from_git_diff", return_value=[]):
            aligned = report._align_hunks(
                [{"header": "@@ a @@", "left": ["x", "z"], "right": ["y"]}]
            )
        self.assertEqual(aligned, [[("x", "y"), ("z", "")]])


if __name__ == "__main__":
    unittest.main()
