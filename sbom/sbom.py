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
import lib.sbom.spdx as spdx
from lib.sbom.cmd.cmd_graph import CmdGraphNode, build_cmd_graph
import time


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
        default="../linux/kernel_build",
        help="Path to the build output tree directory (default: ../linux/kernel_build)",
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


def create_spdx_document(cmd_graph: CmdGraphNode) -> spdx.JsonLdDocument:
    person = spdx.Person(
        name="Luis Augenstein",
        externalIdentifier=[
            spdx.ExternalIdentifier(externalIdentifierType="email", identifier="luis.augenstein@tngtech.com")
        ],
    )
    creation_info = spdx.CreationInfo(createdBy=[person.spdxId])

    software_package = spdx.SoftwarePackage(
        name="amazing-widget",
        software_packageVersion="1.0",
        software_downloadLocation="http://dl.example.com/amazing-widget_1.0.0.tar",
        builtTime="2024-03-06T00:00:00Z",
        originatedBy=[person.spdxId],
        verifiedUsing=[spdx.Hash(hashValue="f3f60ce8615d1cfb3f6d7d149699ab53170ce0b8f24f841fb616faa50151082d")],
    )
    software_file1 = spdx.SoftwareFile(
        name="/usr/bin/amazing-widget",
        builtTime="2024-03-05T00:00:00Z",
        originatedBy=[person.spdxId],
        software_primaryPurpose="executable",
        software_additionalPurpose=["application"],
        software_copyrightText="Copyright 2024, Joshua Watt",
        verifiedUsing=[spdx.Hash(hashValue="ee4f96ed470ea288be281407dacb380fd355886dbd52c8c684dfec3a90e78f45")],
    )
    software_file2 = spdx.SoftwareFile(
        name="/etc/amazing-widget.cfg",
        builtTime="2024-03-05T00:00:00Z",
        originatedBy=[person.spdxId],
        software_primaryPurpose="configuration",
        verifiedUsing=[spdx.Hash(hashValue="ee4f96ed470ea288be281407dacb380fd355886dbd52c8c684dfec3a90e78f45")],
    )
    relationship = spdx.RelationShipContains(
        from_=software_package.spdxId, to=[software_file1.spdxId, software_file2.spdxId], completeness="complete"
    )

    software_sbom = spdx.SoftwareSbom(
        software_sbomType=["build"],
        rootElement=[software_package.spdxId],
        element=[software_file1.spdxId, software_file2.spdxId],
    )
    spdx_document = spdx.SpdxDocument(
        profileConformance=["core", "software", "licensing", "build"], rootElement=[software_sbom.spdxId]
    )
    return spdx.JsonLdDocument(
        graph=[
            person,
            creation_info,
            software_package,
            software_file1,
            software_file2,
            relationship,
            software_sbom,
            spdx_document,
        ]
    )


def main():
    """Main program"""
    # Parse cli arguments
    args = parse_args()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Build cmd graph
    logging.info(f"Building cmd graph for {args.root_output_in_tree}")
    start_time = time.time()
    cmd_graph = build_cmd_graph(
        root_output_in_tree=Path(args.root_output_in_tree),
        output_tree=Path(os.path.realpath(args.output_tree)),
        src_tree=Path(os.path.realpath(args.src_tree)),
    )
    logging.info(f"Build cmd graph in {time.time() - start_time} seconds")

    # Fill SPDX Document
    doc = create_spdx_document(cmd_graph)

    # Save SPDX Document
    json_string = doc.to_json()
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(json_string)
    logging.info(f"Saved {args.output} successfully")


# Call main method
if __name__ == "__main__":
    main()
