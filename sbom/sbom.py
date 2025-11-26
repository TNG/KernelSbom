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
import sys
import time
import uuid


LIB_DIR = "./lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.spdx.spdxId import SpdxIdGenerator  # noqa: E402
from sbom.spdx_graph.spdx_graph import SpdxIdGeneratorCollection, KernelSbomKind, build_spdx_graphs  # noqa: E402
import sbom.errors as sbom_errors  # noqa: E402
from sbom.path_utils import PathStr, is_relative_to  # noqa: E402
from sbom.cmd_graph import build_cmd_graph, iter_cmd_graph  # noqa: E402
from sbom.spdx import JsonLdSpdxDocument  # noqa: E402


@dataclass
class Args:
    src_tree: PathStr
    output_tree: PathStr
    root_paths: list[PathStr]
    spdx: bool
    used_files: bool
    debug: bool
    spdxId_prefix: str
    spdxId_uuid: uuid.UUID
    build_type: str
    package_license: str
    package_version: str | None
    package_copyright_text: str | None
    prettify_json: bool


def _parse_args() -> Args:
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="Generate SPDX SBOM from kernel sources and build artifacts",
    )
    parser.add_argument(
        "--src-tree",
        default="../linux",
        help="Path to the Linux kernel source tree (default: ../linux)",
    )
    parser.add_argument(
        "--output-tree",
        default="../linux/kernel_build",
        help="Path to the build output tree directory (default: ../linux/kernel_build)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--roots",
        nargs="+",
        default="arch/x86/boot/bzImage",
        help="Space-separated list of paths (relative to --output-tree) on which the SBOM will be based. "
        "Cannot be used together with --roots-file. (default: arch/x86/boot/bzImage)",
    )
    group.add_argument(
        "--roots-file",
        help="Path to a file containing the root paths (one per line). Cannot be used together with --roots.",
    )
    parser.add_argument(
        "--spdx",
        action="store_true",
        default=False,
        help="Whether to create sbom-source.spdx.json, sbom-build.spdx.json and sbom-output.spdx.json documents",
    )
    parser.add_argument(
        "--used-files",
        action="store_true",
        default=False,
        help="Whether to create the sbom.used-files.txt file, a flat list of all source files used for the kernel build. "
        "Note, if src-tree and output-tree are equal it is not possible to reliably classify source files. "
        "In this case sbom.used-files.txt will contain all files used for the kernel build including all build artifacts. (default: False)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Debug level (default: False)",
    )

    # SPDX specific settings
    parser.add_argument(
        "--spdxId-prefix",
        default="urn:spdx.dev:",
        help="The prefix to use for all spdxId properties. (default: urn:spdx.dev:)",
    )
    parser.add_argument(
        "--spdxId-uuid",
        default=None,
        help="The uuid to use for all spdxId properties to make the SPDX documents reproducible. By default a random uuid is generated.",
    )
    parser.add_argument(
        "--build-type",
        default="urn:spdx.dev:Kbuild",
        help="The SPDX buildType property to use for all Build elements. (default: urn:spdx.dev:Kbuild)",
    )
    parser.add_argument(
        "--package-license",
        default="NOASSERTION",
        help="The SPDX licenseExpression property to use for the LicenseExpression linked to all SPDX Package elements. (default: NOASSERTION)",
    )
    parser.add_argument(
        "--package-version",
        default=None,
        help="The SPDX packageVersion property to use for all SPDX Package elements. (default: None)",
    )
    parser.add_argument(
        "--package-copyright-text",
        default=None,
        help="The SPDX copyrightText property to use for all SPDX Package elements. If not provided, the tool will attempt to read the top-level 'COPYING' file from the source tree.",
    )
    parser.add_argument(
        "--prettify-json",
        action="store_true",
        default=False,
        help="Whether to pretty print the gnerated spdx.json documents (default: False)",
    )

    # Extract and validate arguments
    args = vars(parser.parse_args())

    src_tree = os.path.realpath(args["src_tree"])
    output_tree = os.path.realpath(args["output_tree"])
    root_paths = []
    if args["roots_file"]:
        with open(args["roots_file"], "rt") as f:
            root_paths = [root.strip() for root in f.readlines()]
    else:
        root_paths = args["roots"]

    if not os.path.exists(src_tree):
        raise argparse.ArgumentTypeError(f"--src-tree {src_tree} does not exist")
    if not os.path.exists(output_tree):
        raise argparse.ArgumentTypeError(f"--output-tree {output_tree} does not exist")
    for root_path in root_paths:
        if not os.path.exists(os.path.join(output_tree, root_path)):
            raise argparse.ArgumentTypeError(
                f"path to root artifact {os.path.join(output_tree, root_path)} does not exist"
            )

    spdx = args["spdx"]
    used_files = args["used_files"]
    debug = args["debug"]

    spdxId_prefix = args["spdxId_prefix"]
    spdxId_uuid = uuid.UUID(args["spdxId_uuid"]) if args["spdxId_uuid"] is not None else uuid.uuid4()
    build_type = args["build_type"]
    package_license = args["package_license"]
    package_version = args["package_version"] if args["package_version"] is not None else None
    package_copyright_text: str | None = None
    if args["package_copyright_text"] is not None:
        package_copyright_text = args["package_copyright_text"]
    elif os.path.isfile(copying_path := os.path.join(src_tree, "COPYING")):
        with open(copying_path, "r") as f:
            package_copyright_text = f.read()

    prettify_json = args["prettify_json"]

    # Validate arguments

    return Args(
        src_tree,
        output_tree,
        root_paths,
        spdx,
        used_files,
        debug,
        spdxId_prefix,
        spdxId_uuid,
        build_type,
        package_license,
        package_version,
        package_copyright_text,
        prettify_json,
    )


def main():
    # Define output filenames
    SBOM_FILE_NAMES = {
        KernelSbomKind.SOURCE: "sbom-source.spdx.json",
        KernelSbomKind.BUILD: "sbom-build.spdx.json",
        KernelSbomKind.OUTPUT: "sbom-output.spdx.json",
    }
    SBOM_USED_FILES_NAME = "sbom.used-files.txt"

    # Parse cli arguments
    args = _parse_args()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Build cmd graph
    logging.debug("Start building cmd graph")
    start_time = time.time()
    cmd_graph = build_cmd_graph(args.root_paths, args.output_tree, args.src_tree)
    logging.debug(f"Built cmd graph in {time.time() - start_time} seconds")

    # Save used files
    if args.used_files:
        if args.src_tree == args.output_tree:
            logging.warning(
                f"Cannot distinguish source and output files because source and output trees are equal. Extracting all files from cmd graph for {SBOM_USED_FILES_NAME}"
            )
            used_files = [os.path.relpath(node.absolute_path, args.src_tree) for node in iter_cmd_graph(cmd_graph)]
            logging.debug(f"Found {len(used_files)} files in cmd graph.")
        else:
            used_files = [
                os.path.relpath(node.absolute_path, args.src_tree)
                for node in iter_cmd_graph(cmd_graph)
                if is_relative_to(node.absolute_path, args.src_tree)
                and not is_relative_to(node.absolute_path, args.output_tree)
            ]
            logging.debug(f"Found {len(used_files)} source files in cmd graph")
        with open(SBOM_USED_FILES_NAME, "w", encoding="utf-8") as f:
            f.write("\n".join(str(file_path) for file_path in used_files))
        logging.info(f"Successfully saved {SBOM_USED_FILES_NAME}")

    if args.spdx is False:
        return

    # Build SPDX Document
    logging.debug("Start generating SPDX graph based on cmd graph")
    start_time = time.time()

    spdx_id_base_namespace = f"{args.spdxId_prefix}{args.spdxId_uuid}/"
    spdx_id_generators = SpdxIdGeneratorCollection(
        base=SpdxIdGenerator(prefix="p", namespace=spdx_id_base_namespace),
        source=SpdxIdGenerator(prefix="s", namespace=f"{spdx_id_base_namespace}source/"),
        build=SpdxIdGenerator(prefix="b", namespace=f"{spdx_id_base_namespace}build/"),
        output=SpdxIdGenerator(prefix="o", namespace=f"{spdx_id_base_namespace}output/"),
    )

    spdx_graphs = build_spdx_graphs(
        cmd_graph,
        args.output_tree,
        args.src_tree,
        args.build_type,
        args.package_license,
        args.package_version,
        args.package_copyright_text,
        spdx_id_generators,
    )
    logging.debug(f"Generated SPDX graph in {time.time() - start_time} seconds")

    for kernel_sbom_kind, spdx_graph in spdx_graphs.items():
        spdx_doc = JsonLdSpdxDocument(graph=spdx_graph)
        spdx_doc.save(SBOM_FILE_NAMES[kernel_sbom_kind], args.prettify_json)
        logging.info(f"Successfully saved {SBOM_FILE_NAMES[kernel_sbom_kind]}")

    # report collected errors in case of failure
    errors = sbom_errors.get()
    if len(errors) > 0:
        logging.error(f"Sbom generation failed with {len(errors)} errors:")
        for error in errors:
            logging.error(error)
        sys.exit(1)


# Call main method
if __name__ == "__main__":
    main()
