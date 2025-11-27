#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH


"""
Compute software bill of materials in SPDX format describing a kernel build.
"""

import logging
import os
import sys
import time

LIB_DIR = "./lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.config import get_config  # noqa: E402
from sbom.spdx.spdxId import SpdxIdGenerator  # noqa: E402
from sbom.spdx_graph.spdx_graph import SpdxIdGeneratorCollection, build_spdx_graphs  # noqa: E402
import sbom.errors as sbom_errors  # noqa: E402
from sbom.path_utils import is_relative_to  # noqa: E402
from sbom.cmd_graph import build_cmd_graph, iter_cmd_graph  # noqa: E402
from sbom.spdx import JsonLdSpdxDocument  # noqa: E402


def main():
    # Read config
    config = get_config()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if config.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Build cmd graph
    logging.debug("Start building cmd graph")
    start_time = time.time()
    cmd_graph = build_cmd_graph(config.root_paths, config.output_tree, config.src_tree)
    logging.debug(f"Built cmd graph in {time.time() - start_time} seconds")

    # Save used files document
    if config.generate_used_files:
        if config.src_tree == config.output_tree:
            logging.warning(
                f"Cannot distinguish source and output files because source and output trees are equal. Extracting all files from cmd graph for {config.used_files_file_name}"
            )
            used_files = [os.path.relpath(node.absolute_path, config.src_tree) for node in iter_cmd_graph(cmd_graph)]
            logging.debug(f"Found {len(used_files)} files in cmd graph.")
        else:
            used_files = [
                os.path.relpath(node.absolute_path, config.src_tree)
                for node in iter_cmd_graph(cmd_graph)
                if is_relative_to(node.absolute_path, config.src_tree)
                and not is_relative_to(node.absolute_path, config.output_tree)
            ]
            logging.debug(f"Found {len(used_files)} source files in cmd graph")
        with open(config.used_files_file_name, "w", encoding="utf-8") as f:
            f.write("\n".join(str(file_path) for file_path in used_files))
        logging.info(f"Successfully saved {config.used_files_file_name}")

    if config.generate_spdx is False:
        return

    # Build SPDX Documents
    logging.debug("Start generating SPDX graph based on cmd graph")
    start_time = time.time()

    spdx_id_base_namespace = f"{config.spdxId_prefix}{config.spdxId_uuid}/"
    spdx_id_generators = SpdxIdGeneratorCollection(
        base=SpdxIdGenerator(prefix="p", namespace=spdx_id_base_namespace),
        source=SpdxIdGenerator(prefix="s", namespace=f"{spdx_id_base_namespace}source/"),
        build=SpdxIdGenerator(prefix="b", namespace=f"{spdx_id_base_namespace}build/"),
        output=SpdxIdGenerator(prefix="o", namespace=f"{spdx_id_base_namespace}output/"),
    )

    spdx_graphs = build_spdx_graphs(
        cmd_graph,
        spdx_id_generators,
        config,
    )
    logging.debug(f"Generated SPDX graph in {time.time() - start_time} seconds")

    for kernel_sbom_kind, spdx_graph in spdx_graphs.items():
        spdx_doc = JsonLdSpdxDocument(graph=spdx_graph)
        spdx_doc.save(config.spdx_file_names[kernel_sbom_kind], config.prettify_json)
        logging.info(f"Successfully saved {config.spdx_file_names[kernel_sbom_kind]}")

    # Report collected errors in case of failure
    errors = sbom_errors.get()
    if len(errors) > 0:
        logging.error(f"Sbom generation failed with {len(errors)} errors:")
        for error in errors:
            logging.error(error)
        sys.exit(1)


# Call main method
if __name__ == "__main__":
    main()
