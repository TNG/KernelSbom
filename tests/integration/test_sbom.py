# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from kernel_sbom.__main__ import main

DATA_PATH = Path(__file__).parent.parent / "integration_data"


class TestSbom(unittest.TestCase):
    def test_sbom(self):
        argv = [
            "kernel-sbom",
            "--src-tree",
            str(os.path.relpath(DATA_PATH / "linux", os.getcwd())),
            "--obj-tree",
            str(os.path.relpath(DATA_PATH / "linux" / "kernel_build", os.getcwd())),
            "--roots",
            "arch/x86/boot/bzImage",
            "--output-directory",
            str(DATA_PATH),
            "--created",
            "2025-12-09",
            "--prettify-json",
            "--generate-spdx",
            "--generate-used-files",
        ]
        env = {"SRCARCH": "x86"}

        with patch.object(sys, "argv", argv), patch.dict(os.environ, env, clear=True):
            main()

        # Assert generated output documents are binary equal to the target documents
        output_documents = [
            "sbom-source.spdx.json",
            "sbom-build.spdx.json",
            "sbom-output.spdx.json",
            "sbom.used-files.txt",
        ]
        for output_document in output_documents:
            generated_file = DATA_PATH / output_document
            target_file = DATA_PATH / f"target-{output_document}"
            self.assertEqual(
                generated_file.read_bytes(),
                target_file.read_bytes(),
                f"File {output_document} does not match {target_file}",
            )
