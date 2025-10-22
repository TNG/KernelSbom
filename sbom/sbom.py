#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


"""
Compute software bill of materials in SPDX format describing a kernel build.
"""

import argparse
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import lib.sbom.spdx as spdx
from lib.sbom.cmd.cmd_graph import CmdGraph, build_cmd_graph, iter_cmd_graph
import time


@dataclass
class Args:
    src_tree: Path
    output_tree: Path
    root_outputs_in_tree: list[Path]
    spdx: Path | None
    used_files: Path | None
    debug: bool


def _parse_args() -> Args:
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
        "--root-outputs-in-tree",
        nargs="+",
        default=["arch/x86/boot/bzImage", "modules.order"],
        help="Space-separated list of paths (relative to --output-tree) on which the SBOM will be based (default: arch/x86/boot/bzImage modules.order)",
    )
    parser.add_argument(
        "--spdx",
        default="sbom.spdx.json",
        help="Path to create the SPDX document, or 'none' to disable (default: sbom.spdx.json)",
    )
    parser.add_argument(
        "--used-files",
        default="sbom.used_files.txt",
        help="Path to create the a flat list of all source files used for the kernel build, or 'none' to disable (default: sbom.used_files.txt)",
    )
    parser.add_argument("-d", "--debug", action="store_true", default=False, help="Debug level (default: False)")

    # Extract arguments
    args = vars(parser.parse_args())
    src_tree = Path(os.path.realpath(args["src_tree"]))
    output_tree = Path(os.path.realpath(args["output_tree"]))
    root_outputs_in_tree = [Path(root) for root in args["root_outputs_in_tree"]]
    spdx = Path(args["spdx"]) if args["spdx"] != "none" else None
    used_files = Path(args["used_files"]) if args["used_files"] != "none" else None
    debug = args["debug"]

    # Validate arguments
    if not src_tree.exists():
        raise argparse.ArgumentTypeError(f"src-tree {str(src_tree)} does not exist")
    if not output_tree.exists():
        raise argparse.ArgumentTypeError(f"output-tree {str(output_tree)} does not exist")
    for root_output_in_tree in root_outputs_in_tree:
        if not (output_tree / root_output_in_tree).exists():
            raise argparse.ArgumentTypeError(
                f"root-output-in-tree {str(output_tree / root_output_in_tree)} does not exist"
            )

    return Args(src_tree, output_tree, root_outputs_in_tree, spdx, used_files, debug)


def create_spdx_document(cmd_graph: CmdGraph) -> spdx.JsonLdDocument:
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
    args = _parse_args()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Build cmd graph
    logging.info("Start building cmd graph")
    start_time = time.time()
    cmd_graph = build_cmd_graph(args.root_outputs_in_tree, args.output_tree, args.src_tree)
    logging.info(f"Built cmd graph in {time.time() - start_time} seconds")

    # Save used files
    if args.used_files is not None:
        if args.src_tree == args.output_tree:
            logging.warning(
                "Cannot distinguish source and output files because source and output tree are equal. Extracting all files from cmd graph"
            )
            used_files = [os.path.relpath(node.absolute_path, args.src_tree) for node in iter_cmd_graph(cmd_graph)]
            logging.info(f"Found {len(used_files)} files in cmd graph.")
        else:
            logging.info("Extracting source files from cmd graph")
            used_files = [
                os.path.relpath(node.absolute_path, args.src_tree)
                for node in iter_cmd_graph(cmd_graph)
                if not node.absolute_path.is_relative_to(args.output_tree)
            ]
            logging.info(f"Found {len(used_files)} source files in cmd graph.")
        with open(args.used_files, "w", encoding="utf-8") as f:
            f.write("\n".join(str(file_path) for file_path in used_files))
        logging.info(f"Saved {args.used_files} successfully")

    if args.spdx is None:
        return

    # Fill SPDX Document
    logging.info("Generating SPDX Document based on cmd graph")
    spdx_doc = create_spdx_document(cmd_graph)

    # Save SPDX Document
    spdx_json = spdx_doc.to_json()
    with open(args.spdx, "w", encoding="utf-8") as f:
        f.write(spdx_json)
    logging.info(f"Saved {str(args.spdx)} successfully")


# Call main method
if __name__ == "__main__":
    main()
