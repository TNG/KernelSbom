#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Copyright(c) 2025: Luis Augenstein <luis.augenstein@tngtech.com>.

"""
Compute software bill of materials in SPDX format describing a kernel build.
"""

import argparse
import logging
import os
import sys

# Import Python modules

LIB_DIR = "lib/sbom"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

import spdx
from cmd_parser import cmdfiles_in_dir, parse_cmd_file

def initial_spdx_document():
    return

def main():
    """Main program"""
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter, description="Generate SPDX SBOM from kernel sources and build artifacts",)
    parser.add_argument("--src-tree", required=True, help="Path to the Linux kernel source tree (e.g. ~/linux)")
    parser.add_argument("--output-tree", required=True, help="Path to the build output tree directory (e.g. ~/linux/build)")
    parser.add_argument("--root-outputs", required=True, nargs='+', help="list of root build outputs (e.g. vmlinux) the SBOM will be based on.")
    parser.add_argument("--output", default="sbom.spdx.json", help="Path where to create the SPDX document (default: sbom.spdx.json)")
    parser.add_argument("-d", "--debug", type=int, default=0, help="debug level")
    args = parser.parse_args()

    if args.debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    logging.basicConfig(level=level, format="[%(levelname)s] %(message)s")
    # logger = logging.getLogger('sbom')
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

    for cmd_file_path in cmdfiles_in_dir(directory=args.output_tree):
        cmd_file = parse_cmd_file(cmd_file_path)
        # spdx_entity = spdx_entity_from_cmd_file(cmd_file)
        # doc.graph.append(spdx_entity)

    json_string = doc.to_json()
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(json_string)
    

# Call main method
if __name__ == "__main__":
    main()
