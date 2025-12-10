#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

# ruff: noqa: E402

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

from sbom.config import get_config
import sbom.sbom_logging as sbom_logging
from sbom.path_utils import is_relative_to
from sbom.spdx import JsonLdSpdxDocument, SpdxIdGenerator
from sbom.spdx.core import CreationInfo
from sbom.spdx_graph import SpdxIdGeneratorCollection, build_spdx_graphs
from sbom.cmd_graph import CmdGraph


def main():
    # Read config
    config = get_config()

    # Configure logging
    logging.basicConfig(level=logging.DEBUG if config.debug else logging.INFO, format="[%(levelname)s] %(message)s")

    # Build cmd graph
    logging.debug("Start building cmd graph")
    start_time = time.time()
    cmd_graph = CmdGraph.create(config.root_paths, config)
    logging.debug(f"Built cmd graph in {time.time() - start_time} seconds")

    # Save used files document
    if config.generate_used_files:
        if config.src_tree == config.obj_tree:
            sbom_logging.warning(
                "Extracting all files from the cmd graph to {used_files_file_name} instead of only source files because source files cannot be reliably classified when the source and object trees are identical.",
                used_files_file_name=config.used_files_file_name,
            )
            used_files = [os.path.relpath(node.absolute_path, config.src_tree) for node in cmd_graph]
            logging.debug(f"Found {len(used_files)} files in cmd graph.")
        else:
            used_files = [
                os.path.relpath(node.absolute_path, config.src_tree)
                for node in cmd_graph
                if is_relative_to(node.absolute_path, config.src_tree)
                and not is_relative_to(node.absolute_path, config.obj_tree)
            ]
            logging.debug(f"Found {len(used_files)} source files in cmd graph")
        if not sbom_logging.has_errors() or config.write_output_on_error:
            with open(os.path.join(config.output_directory, config.used_files_file_name), "w", encoding="utf-8") as f:
                f.write("\n".join(str(file_path) for file_path in used_files))
            logging.debug(f"Successfully saved {os.path.join(config.output_directory, config.used_files_file_name)}")

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

    # Report collected warnings and errors in case of failure
    warning_summary = sbom_logging.summarize_warnings()
    error_summary = sbom_logging.summarize_errors()

    if not sbom_logging.has_errors() or config.write_output_on_error:
        for kernel_sbom_kind, spdx_graph in spdx_graphs.items():
            creation_info = next(element for element in spdx_graph if isinstance(element, CreationInfo))
            creation_info.comment = "\n".join([warning_summary, error_summary]).strip()
            spdx_doc = JsonLdSpdxDocument(graph=spdx_graph)
            save_path = os.path.join(config.output_directory, config.spdx_file_names[kernel_sbom_kind])
            spdx_doc.save(save_path, config.prettify_json)
            logging.debug(f"Successfully saved {save_path}")

    if warning_summary:
        logging.warning(warning_summary)
    if error_summary:
        logging.error(error_summary)
        if not config.write_output_on_error:
            logging.info(
                "You can use --write-output-on-error to generate output documents even when errors occur. "
                "Note that in this case the documents may be incomplete."
            )
        sys.exit(1)


# Call main method
if __name__ == "__main__":
    main()
