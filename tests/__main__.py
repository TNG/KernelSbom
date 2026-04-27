# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

"""
Test runner for kernel-sbom.

Invocation:
  # Unit tests (default)
  python -m tests

  # Unit + integration tests
  SRCARCH=x86 python -m tests --integration
"""

import argparse
import sys
import unittest


def main():
    parser = argparse.ArgumentParser(description="Run kernel-sbom tests")
    parser.add_argument(
        "--integration",
        action="store_true",
        help="Also run integration tests (require SRCARCH to be set)",
    )
    args = parser.parse_args()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Always include unit tests
    suite.addTests(loader.discover(start_dir="tests/cmd_graph", pattern="test_*.py"))
    suite.addTests(loader.discover(start_dir="tests/spdx_graph", pattern="test_*.py"))

    if args.integration:
        suite.addTests(loader.discover(start_dir="tests/integration", pattern="test_*.py"))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
