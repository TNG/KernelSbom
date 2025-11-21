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
    prettify_json: bool
    used_files: bool
    spdx_uri_prefix: str
    package_name: str
    package_license: str
    build_version: str
    debug: bool


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

    # Spdx specific settings
    parser.add_argument(
        "--prettify-json",
        action="store_true",
        default=False,
        help="Whether to pretty print the gnerated spdx.json documents (default: False)",
    )
    parser.add_argument(
        "--spdx-uri-prefix",
        default="https://spdx.org/spdxdocs/",
        help="The uri prefix to be used for all 'spdxId' fields in the spdx document (default: https://spdx.org/spdxdocs/)",
    )
    parser.add_argument(
        "--package-name",
        default="Linux Kernel",
        help="The name of the Spdx Package element in sbom-output.spdx.json containing the artifacts provided in --roots. (default: Linux Kernel)",
    )
    parser.add_argument(
        "--package-license",
        default="NOASSERTION",
        help="The license expression to use when generating the Spdx Package element. (default: NOASSERTION)",
    )
    parser.add_argument(
        "--build-version",
        default="NOASSERTION",
        help="The version of the build that created the artifacts provided in --roots. Will be used when generating the Spdx Package element. (default: NOASSERTION)",
    )

    parser.add_argument("-d", "--debug", action="store_true", default=False, help="Debug level (default: False)")

    # Extract arguments
    args = vars(parser.parse_args())
    src_tree = os.path.realpath(args["src_tree"])
    output_tree = os.path.realpath(args["output_tree"])
    root_paths = []
    if args["roots_file"]:
        with open(args["roots_file"], "rt") as f:
            root_paths = [root.strip() for root in f.readlines()]
    else:
        root_paths = args["roots"]
    spdx = args["spdx"]
    used_files = args["used_files"]
    spdx_uri_prefix = args["spdx_uri_prefix"]
    package_name = args["package_name"]
    package_license = args["package_license"]
    build_version = args["build_version"]
    prettify_json = args["prettify_json"]
    debug = args["debug"]

    # Validate arguments
    if not os.path.exists(src_tree):
        raise argparse.ArgumentTypeError(f"--src-tree {src_tree} does not exist")
    if not os.path.exists(output_tree):
        raise argparse.ArgumentTypeError(f"--output-tree {output_tree} does not exist")
    for root_path in root_paths:
        if not os.path.exists(os.path.join(output_tree, root_path)):
            raise argparse.ArgumentTypeError(
                f"path to root artifact {os.path.join(output_tree, root_path)} does not exist"
            )

    return Args(
        src_tree,
        output_tree,
        root_paths,
        spdx,
        prettify_json,
        used_files,
        spdx_uri_prefix,
        package_name,
        package_license,
        build_version,
        debug,
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
        logging.info(f"Saved {SBOM_USED_FILES_NAME} successfully")

    if args.spdx is False:
        return

    # Build SPDX Document
    logging.debug("Start generating Spdx graph based on cmd graph")
    start_time = time.time()

    spdx_id_base_namespace = f"{args.spdx_uri_prefix}/{uuid.uuid4()}/"
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
        args.spdx_uri_prefix,
        args.package_name,
        args.package_license,
        args.build_version,
        spdx_id_generators,
    )
    logging.debug(f"Generated Spdx graph in {time.time() - start_time} seconds")

    for kernel_sbom_kind, spdx_graph in spdx_graphs.items():
        spdx_doc = JsonLdSpdxDocument(graph=spdx_graph)
        spdx_doc.save(SBOM_FILE_NAMES[kernel_sbom_kind], args.prettify_json)
        logging.info(f"Saved {SBOM_FILE_NAMES[kernel_sbom_kind]} successfully")

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
