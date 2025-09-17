#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>
#
# SPDX-License-Identifier: GPL-2.0-only

"""
Compute software bill of materials in SPDX format describing a kernel build.
"""

import argparse
import logging
import os
from pathlib import Path
import sys

LIB_DIR = "lib/sbom"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

import spdx
from cmd.cmd_graph import build_cmd_graph, pretty_print_cmd_graph


def initial_spdx_document():
    return


def main():
    """Main program"""
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
        help="root build output path relative to --output-tree the SBOM will be based on (default: vmlinux)",
    )
    parser.add_argument(
        "--output", default="sbom.spdx.json", help="Path where to create the SPDX document (default: sbom.spdx.json)"
    )
    parser.add_argument("-d", "--debug", type=int, default=0, help="debug level (default: 0)")
    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")

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

    doc = spdx.JsonLdDocument(graph=[person, creation_info, spdx_document, software_sbom])

    root_output_path = Path(os.path.realpath(os.path.join(args.output_tree, args.root_output_in_tree)))
    logging.info(f"Building cmd graph for {root_output_path}")
    cmd_graph = build_cmd_graph(root_output_path)
    logging.info("Parsed cmd graph:\n" + pretty_print_cmd_graph(cmd_graph))

    json_string = doc.to_json()
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(json_string)

    logging.info(f"Saved {args.output} successfully")


# Call main method
if __name__ == "__main__":
    main()
