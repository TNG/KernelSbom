# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

# pyright: reportMissingImports=false
# ruff: noqa: E402

from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import os
from importlib import util

# Add the sbom package to the sys.path
SBOM_PATH = Path(__file__).parent.parent / "sbom"
sys.path.append(str(SBOM_PATH))

# Import the sbom.py script as a module with a different name to avoid conflict
sbom_py_spec = util.spec_from_file_location("sbom_script", SBOM_PATH / "sbom.py")
if sbom_py_spec is None or sbom_py_spec.loader is None:
    raise ImportError(f"Could not load spec for sbom.py at {SBOM_PATH / 'sbom.py'}")
sbom_script = util.module_from_spec(sbom_py_spec)
sbom_py_spec.loader.exec_module(sbom_script)

# Imports from the sbom package
from sbom.path_utils import PathStr


class TestSbom(unittest.TestCase):
    data_path: PathStr = os.path.abspath(Path(__file__).parent / "data")

    @staticmethod
    def _set_root_artifact_mtime_for_expected_creation(data_path: PathStr) -> None:
        """SPDX CreationInfo.created is derived from root paths' mtimes; git clone does not preserve them."""
        target_output = Path(data_path) / "target-sbom-output.spdx.json"
        with open(target_output, encoding="utf-8") as f:
            graph = json.load(f)["@graph"]
        creation = next(item for item in graph if item.get("type") == "CreationInfo")
        created_str: str = creation["created"]
        dt = datetime.strptime(created_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        mtime = dt.timestamp()
        bzimage = Path(data_path) / "linux/kernel_build/arch/x86/boot/bzImage"
        os.utime(bzimage, (mtime, mtime))

    @patch.object(
        sys,
        "argv",
        [
            "sbom",
            "--src-tree",
            f"{os.path.relpath(data_path, os.getcwd())}/linux",
            "--obj-tree",
            f"{os.path.relpath(data_path, os.getcwd())}/linux/kernel_build",
            "--roots",
            "arch/x86/boot/bzImage",
            "--output-directory",
            f"{data_path}",
            "--prettify-json",
            "--generate-spdx",
            "--generate-used-files",
        ],
    )
    def test_sbom(self):
        # Run the sbom.py script to generate the output documents
        os.environ.clear()
        os.environ["SRCARCH"] = "x86"
        self._set_root_artifact_mtime_for_expected_creation(self.data_path)
        sbom_script.main()

        # Assert generated output documents are binary equal to the target documents
        output_documents = [
            "sbom-source.spdx.json",
            "sbom-build.spdx.json",
            "sbom-output.spdx.json",
            "sbom.used-files.txt",
        ]
        for output_document in output_documents:
            generated_file = os.path.join(self.data_path, output_document)
            target_file = os.path.join(self.data_path, f"target-{output_document}")
            with open(generated_file, "rb") as f_generated, open(target_file, "rb") as f_target:
                generated_content = f_generated.read()
                target_content = f_target.read()
            self.assertEqual(generated_content, target_content, f"File {output_document} does not match {target_file}")
