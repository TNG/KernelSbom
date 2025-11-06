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
from pathlib import Path

LIB_DIR = "./lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.spdx.spdxId import set_spdx_uri_prefix  # noqa: E402
from sbom.spdx_graph import build_spdx_graph  # noqa: E402
from sbom.spdx.serialization import JsonLdDocument  # noqa: E402
from sbom.cmd.cmd_graph import build_cmd_graph, iter_cmd_graph  # noqa: E402
import time  # noqa: E402
import sbom.errors as sbom_errors  # noqa: E402


@dataclass
class Args:
    src_tree: Path
    output_tree: Path
    root_paths: list[Path]
    spdx: Path | None
    used_files: Path | None
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
        "--src-tree", default="../linux", help="Path to the Linux kernel source tree (default: ../linux)"
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
        default=None,
        help="Space-separated list of paths (relative to --output-tree) on which the SBOM will be based. "
        "Cannot be used together with --roots-file. (default: arch/x86/boot/bzImage)",
    )
    group.add_argument(
        "--roots-file",
        help="Path to a file containing the root paths (one per line). Cannot be used together with --roots.",
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
    parser.add_argument(
        "--spdx-uri-prefix",
        default="https://kernel.org/",
        help="The uri prefix to be used for all 'spdxId' fields in the spdx document",
    )
    parser.add_argument(
        "--package-name",
        default="Linux Kernel",
        help="The name of the Spdx Package element containing the artifacts provided in --roots. (default: Linux Kernel)",
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
    src_tree = Path(os.path.realpath(args["src_tree"]))
    output_tree = Path(os.path.realpath(args["output_tree"]))
    root_paths = []
    if args["roots"]:
        root_paths = [Path(root) for root in args["roots"]]
    elif args["roots_file"]:
        with open(args["roots_file"], "rt") as f:
            root_paths = [Path(root.strip()) for root in f.readlines()]
    spdx = Path(args["spdx"]) if args["spdx"] != "none" else None
    used_files = Path(args["used_files"]) if args["used_files"] != "none" else None
    spdx_uri_prefix = args["spdx_uri_prefix"]
    package_name = args["package_name"]
    package_license = args["package_license"]
    build_version = args["build_version"]
    debug = args["debug"]

    # Validate arguments
    if not src_tree.exists():
        raise argparse.ArgumentTypeError(f"--src-tree {str(src_tree)} does not exist")
    if not output_tree.exists():
        raise argparse.ArgumentTypeError(f"--output-tree {str(output_tree)} does not exist")
    for root_path in root_paths:
        if not (output_tree / root_path).exists():
            raise argparse.ArgumentTypeError(f"path to root artifact {str(output_tree / root_path)} does not exist")

    return Args(
        src_tree,
        output_tree,
        root_paths,
        spdx,
        used_files,
        spdx_uri_prefix,
        package_name,
        package_license,
        build_version,
        debug,
    )


def main():
    # Parse cli arguments
    args = _parse_args()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Build cmd graph
    logging.info("Start building cmd graph")
    start_time = time.time()
    cmd_graph = build_cmd_graph(args.root_paths, args.output_tree, args.src_tree)
    logging.info(f"Built cmd graph in {time.time() - start_time} seconds")

    # Save used files
    if args.used_files is not None:
        if args.src_tree == args.output_tree:
            logging.warning(
                "Cannot distinguish source and output files because source and output trees are equal. Extracting all files from cmd graph"
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

    # Build SPDX Document
    logging.info("Generating SPDX document based on cmd graph")
    set_spdx_uri_prefix(args.spdx_uri_prefix)
    spdx_graph = build_spdx_graph(
        cmd_graph,
        args.output_tree,
        args.src_tree,
        args.spdx_uri_prefix,
        args.package_name,
        args.package_license,
        args.build_version,
    )
    spdx_doc = JsonLdDocument(graph=spdx_graph)

    # Save SPDX Document
    spdx_json = spdx_doc.to_jsonld()
    with open(args.spdx, "w", encoding="utf-8") as f:
        f.write(spdx_json)
    logging.info(f"Saved {str(args.spdx)} successfully")

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
