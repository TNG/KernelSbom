#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2025: Luis Augenstein <luis.augenstein@tngtech.com>.

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
from cmd_parser import parse_cmd_file

def initial_spdx_document():
    return

def main():
    """Main program"""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="Generate SPDX SBOM from kernel sources and build artifacts",)
    parser.add_argument("--src-tree", default="../linux", required=True, help="Path to the Linux kernel source tree (default: ../linux)")
    parser.add_argument("--output-tree", default="../linux/kernel-build", required=True, help="Path to the build output tree directory (default: ../linux/kernel-build)")
    parser.add_argument("--root-output", default="vmlinux", required=True, help="root build output path the SBOM will be based on relative to --output-tree (default: vmlinux)")
    parser.add_argument("--output", default="sbom.spdx.json", help="Path where to create the SPDX document (default: sbom.spdx.json)")
    parser.add_argument("-d", "--debug", type=int, default=0, help="debug level (default: 0)")
    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")

    person = spdx.Person(
        name="Luis Augenstein",
        externalIdentifier=[spdx.ExternalIdentifier(
            externalIdentifierType="email",
            identifier="luis.augenstein@tngtech.com"
        )]
    )
    creation_info = spdx.CreationInfo(createdBy=[person.spdxId])
    software_sbom = spdx.SoftwareSbom(
        software_sbomType=["build"]
    )
    spdx_document = spdx.SpdxDocument(
        profileConformance=["core", "software", "licensing", "build"],
        rootElement=[software_sbom.spdxId]
    )

    doc = spdx.JsonLdDocument(graph=[person, creation_info, spdx_document, software_sbom])

    root_output = Path(args.root_output)
    cmd_file = parse_cmd_file(os.path.join(args.output_tree, root_output.parent, f".{root_output.name}.cmd"))
    logging.info(f"Parsed: {cmd_file}")

    json_string = doc.to_json()
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(json_string)
    
    logging.info(f"Saved {args.output} successfully")
    

# Call main method
if __name__ == "__main__":
    main()
