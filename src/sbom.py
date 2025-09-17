#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

"""
Compute software bill of materials in SPDX format describing a kernel build.
"""

import argparse
from dataclasses import dataclass
import logging
import os
from pathlib import Path
from lib.sbom import spdx
from lib.sbom.cmd.cmd_graph import build_cmd_graph


@dataclass
class Args:
    src_tree: str
    output_tree: str
    root_output_in_tree: str
    output: str
    debug: bool


def parse_args() -> Args:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="Generate SPDX SBOM from kernel sources and build artifacts",
    )
    parser.add_argument(
        "--src-tree", default="../linux", help="Path to the Linux kernel source tree (default: ../linux)"
    )
    parser.add_argument(
        "--output-tree",
        default="../linux/kernel-build",
        help="Path to the build output tree directory (default: ../linux/kernel-build)",
    )
    parser.add_argument(
        "--root-output-in-tree",
        default="vmlinux",
        help="Root build output path relative to --output-tree the SBOM will be based on (default: vmlinux)",
    )
    parser.add_argument(
        "--output", default="sbom.spdx.json", help="Path where to create the SPDX document (default: sbom.spdx.json)"
    )
    parser.add_argument("-d", "--debug", action="store_true", default=False, help="Debug level (default: False)")

    ns = parser.parse_args()
    return Args(**vars(ns))


def create_basic_spdx_document() -> spdx.JsonLdDocument:
    person = spdx.Person(
        name="Luis Augenstein",
        externalIdentifier=[
            spdx.ExternalIdentifier(externalIdentifierType="email", identifier="luis.augenstein@tngtech.com")
        ],
    )
    creation_info = spdx.CreationInfo(createdBy=[person.spdxId])
    software_sbom = spdx.SoftwareSbom(software_sbomType=["build"])
    spdx_document = spdx.SpdxDocument(
        profileConformance=["core", "software", "licensing", "build"], rootElement=[software_sbom.spdxId]
    )
    return spdx.JsonLdDocument(graph=[person, creation_info, spdx_document, software_sbom])


def main():
    """Main program"""
    # Parse cli arguments
    args = parse_args()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Create initial SPDX document
    doc = create_basic_spdx_document()

    # Build cmd graph

    logging.info(f"Building cmd graph for {args.root_output_in_tree}")
    cmd_graph = build_cmd_graph(  # noqa: F841 # type: ignore
        root_output_in_tree=Path(args.root_output_in_tree), output_tree=Path(os.path.realpath(args.output_tree))
    )

    # Fill SPDX Document
    # TODO

    # Save SPDX Document
    json_string = doc.to_json()
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(json_string)
    logging.info(f"Saved {args.output} successfully")


# Call main method
if __name__ == "__main__":
    main()
