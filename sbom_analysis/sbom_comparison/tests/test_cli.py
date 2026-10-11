# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Luis Augenstein

"""End-to-end tests for the sbom-compare command line interface."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from sbom_compare.cli import main


def file_element(spdx_id: str, name: str) -> dict:
    return {"type": "software_File", "spdxId": spdx_id, "creationInfo": "_:creationinfo", "name": name}


def document(files: list[str]) -> dict:
    graph = [
        {"type": "SpdxDocument", "spdxId": "b:0", "creationInfo": "_:creationinfo", "name": "doc"},
        {"type": "CreationInfo", "@id": "_:creationinfo", "specVersion": "3.0.1"},
    ]
    graph += [file_element(f"b:{index + 1}", name) for index, name in enumerate(files)]
    return {"@context": ["https://example.org/spdx-context.jsonld", {}], "@graph": graph}


class TestCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.comparison = Path(self._tmp.name) / "comparison"
        (self.comparison / "reference").mkdir(parents=True)
        (self.comparison / "candidate").mkdir(parents=True)
        for name in ("sbom-output.spdx.json", "sbom-build.spdx.json", "sbom-source.spdx.json"):
            reference = document(["kernel/sched/core.c", "init/main.c"])
            candidate = document(["kernel/sched/core.c", "drivers/net/loopback.c"])
            (self.comparison / "reference" / name).write_text(json.dumps(reference), encoding="utf-8")
            (self.comparison / "candidate" / name).write_text(json.dumps(candidate), encoding="utf-8")

    def tearDown(self):
        self._tmp.cleanup()

    def test_successful_comparison(self):
        exit_code = main([str(self.comparison)])
        self.assertEqual(exit_code, 0)

        report = self.comparison / "sbom-compare-report.html"
        self.assertTrue(report.is_file())
        html = report.read_text(encoding="utf-8")
        self.assertIn("Differences found", html)
        self.assertIn("drivers/net/loopback.c", html)
        self.assertIn("init/main.c", html)
        # The unchanged file is filtered out of both sides and must not appear.
        self.assertNotIn("kernel/sched/core.c", html)

    def test_json_report(self):
        exit_code = main([str(self.comparison)])
        self.assertEqual(exit_code, 0)
        json_path = self.comparison / "sbom-compare-report.json"
        self.assertTrue(json_path.is_file())
        data = json.loads(json_path.read_text(encoding="utf-8"))
        build = data["documents"]["sbom-build.spdx.json"]
        self.assertEqual(len(build["removed"]), 1)
        self.assertEqual(len(build["added"]), 1)

    def test_identical_documents(self):
        for name in ("sbom-output.spdx.json", "sbom-build.spdx.json", "sbom-source.spdx.json"):
            content = document(["kernel/sched/core.c"])
            (self.comparison / "reference" / name).write_text(json.dumps(content), encoding="utf-8")
            (self.comparison / "candidate" / name).write_text(json.dumps(content), encoding="utf-8")
        exit_code = main([str(self.comparison)])
        self.assertEqual(exit_code, 0)
        html = (self.comparison / "sbom-compare-report.html").read_text(encoding="utf-8")
        self.assertIn("Semantically identical", html)

    def test_verbose_logging(self):
        exit_code = main([str(self.comparison), "--verbose"])
        self.assertEqual(exit_code, 0)
        self.assertTrue((self.comparison / "sbom-compare-report.html").is_file())

    def test_missing_reference_folder_fails(self):
        shutil.rmtree(self.comparison / "reference")
        exit_code = main([str(self.comparison)])
        self.assertEqual(exit_code, 1)

    def test_missing_document_fails(self):
        (self.comparison / "candidate" / "sbom-build.spdx.json").unlink()
        exit_code = main([str(self.comparison)])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()