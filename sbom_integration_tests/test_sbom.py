# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

# pyright: reportMissingImports=false
# ruff: noqa: E402

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
        os.environ["SRCARCH"] = "x86"
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
