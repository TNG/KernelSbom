# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import argparse
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import os
from typing import Any
import uuid
from sbom.path_utils import PathStr


class KernelSpdxDocumentKind(Enum):
    SOURCE = "source"
    BUILD = "build"
    OUTPUT = "output"


@dataclass
class KernelSbomConfig:
    src_tree: PathStr
    """Absolute path to the Linux kernel source directory."""

    obj_tree: PathStr
    """Absolute path to the build output directory."""

    root_paths: list[PathStr]
    """List of paths to root outputs (relative to obj_tree) to base the SBOM on."""

    generate_spdx: bool
    """Whether to generate SPDX SBOM documents. If False, no SPDX files are created."""

    spdx_file_names: dict[KernelSpdxDocumentKind, str]
    """If `generate_spdx` is True, defines the file names for each SPDX SBOM kind (source, build, output) to store on disk."""

    generate_used_files: bool
    """Whether to generate a flat list of all source files used in the build. If False, no used-files document is created."""

    used_files_file_name: str
    """If `generate_used_files` is True, specifies the file name for the used-files document."""

    output_directory: PathStr
    """Path to the directory where the generated output documents will be saved."""

    debug: bool
    """Whether to enable debug logging."""

    fail_on_unknown_build_command: bool
    """Whether to fail if an unknown build command is encountered in a .cmd file."""

    write_output_on_error: bool
    """Whether to write output documents even if errors occur."""

    created: datetime
    """Datetime to use for the SPDX created property of the CreationInfo element."""

    spdxId_prefix: str
    """Prefix to use for all SPDX element IDs."""

    spdxId_uuid: uuid.UUID
    """UUID used for reproducible SPDX element IDs."""

    build_type: str
    """SPDX buildType property to use for all Build elements."""

    build_id: str | None
    """SPDX buildId property to use for all Build elements."""

    package_license: str
    """License expression applied to all SPDX Packages."""

    package_version: str | None
    """Version string applied to all SPDX Packages."""

    package_copyright_text: str | None
    """Copyright text applied to all SPDX Packages."""

    prettify_json: bool
    """Whether to pretty-print generated SPDX JSON documents."""


def _parse_cli_arguments() -> dict[str, Any]:
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
        "--obj-tree",
        default="../linux/kernel_build",
        help="Path to the build object tree directory (default: ../linux/kernel_build)",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--roots",
        nargs="+",
        default="arch/x86/boot/bzImage",
        help="Space-separated list of paths (relative to --obj-tree) on which the SBOM will be based. "
        "Cannot be used together with --roots-file. (default: arch/x86/boot/bzImage)",
    )
    group.add_argument(
        "--roots-file",
        help="Path to a file containing the root paths (one per line). Cannot be used together with --roots.",
    )
    parser.add_argument(
        "--generate-spdx",
        action="store_true",
        default=False,
        help="Whether to create sbom-source.spdx.json, sbom-build.spdx.json and sbom-output.spdx.json documents",
    )
    parser.add_argument(
        "--generate-used-files",
        action="store_true",
        default=False,
        help="Whether to create the sbom.used-files.txt file, a flat list of all source files used for the kernel build. "
        "Note, if src-tree and obj-tree are equal it is not possible to reliably classify source files. "
        "In this case sbom.used-files.txt will contain all files used for the kernel build including all build artifacts. (default: False)",
    )
    parser.add_argument(
        "--output-directory",
        default=".",
        help="Path to the directory where the generated output documents will be saved. (default: .)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="Enable debug logs (default: False)",
    )

    # Error handling settings
    parser.add_argument(
        "--do-not-fail-on-unknown-build-command",
        action="store_true",
        default=False,
        help=(
            "Whether to fail if an unknown build command is encountered in a .cmd file. "
            "If set to True, errors are logged as warnings instead. "
            "(default: False)"
        ),
    )
    parser.add_argument(
        "--write-output-on-error",
        action="store_true",
        default=False,
        help=(
            "Write output documents even if errors occur. "
            "The resulting documents may be incomplete. A summary of warnings "
            "and errors can be found in the 'comment' property of the CreationInfo element. "
            "(default: False)"
        ),
    )

    # SPDX specific settings
    parser.add_argument(
        "--created",
        default=str(datetime.now()),
        help="The SPDX created property to use for the CreationInfo element in ISO format (YYYY-MM-DD [HH:MM:SS]). (default: datetime.now())",
    )
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
        "--build-id",
        default=None,
        help="The SPDX buildId property to use for all Build elements. If not provided the spdxId of the high level Build element is used as the buildId. (default: None)",
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
        help="The SPDX copyrightText property to use for all SPDX Package elements. If not specified, and if a COPYING file exists in the source tree, the package-copyright-text is set to the content of this file. (default: None)",
    )
    parser.add_argument(
        "--prettify-json",
        action="store_true",
        default=False,
        help="Whether to pretty print the gnerated spdx.json documents (default: False)",
    )

    args = vars(parser.parse_args())
    return args


def get_config() -> KernelSbomConfig:
    # Parse cli arguments
    args = _parse_cli_arguments()

    # Extract and validate cli arguments
    src_tree = os.path.realpath(args["src_tree"])
    obj_tree = os.path.realpath(args["obj_tree"])
    root_paths = []
    if args["roots_file"]:
        with open(args["roots_file"], "rt") as f:
            root_paths = [root.strip() for root in f.readlines()]
    else:
        root_paths = args["roots"]
    _validate_path_arguments(src_tree, obj_tree, root_paths)

    generate_spdx = args["generate_spdx"]
    generate_used_files = args["generate_used_files"]
    output_directory = os.path.realpath(args["output_directory"])
    debug = args["debug"]

    fail_on_unknown_build_command = not args["do_not_fail_on_unknown_build_command"]
    write_output_on_error = args["write_output_on_error"]

    try:
        created = datetime.fromisoformat(args["created"])
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"Invalid date format for argument '--created': '{args['created']}'. Expected ISO format (YYYY-MM-DD [HH:MM:SS])."
        )
    spdxId_prefix = args["spdxId_prefix"]
    spdxId_uuid = uuid.UUID(args["spdxId_uuid"]) if args["spdxId_uuid"] is not None else uuid.uuid4()
    build_type = args["build_type"]
    build_id = args["build_id"]
    package_license = args["package_license"]
    package_version = args["package_version"] if args["package_version"] is not None else None
    package_copyright_text: str | None = None
    if args["package_copyright_text"] is not None:
        package_copyright_text = args["package_copyright_text"]
    elif os.path.isfile(copying_path := os.path.join(src_tree, "COPYING")):
        with open(copying_path, "r") as f:
            package_copyright_text = f.read()
    prettify_json = args["prettify_json"]

    # Hardcoded config
    spdx_file_names = {
        KernelSpdxDocumentKind.SOURCE: "sbom-source.spdx.json",
        KernelSpdxDocumentKind.BUILD: "sbom-build.spdx.json",
        KernelSpdxDocumentKind.OUTPUT: "sbom-output.spdx.json",
    }
    used_files_file_name = "sbom.used-files.txt"

    return KernelSbomConfig(
        src_tree=src_tree,
        obj_tree=obj_tree,
        root_paths=root_paths,
        generate_spdx=generate_spdx,
        spdx_file_names=spdx_file_names,
        generate_used_files=generate_used_files,
        used_files_file_name=used_files_file_name,
        output_directory=output_directory,
        debug=debug,
        fail_on_unknown_build_command=fail_on_unknown_build_command,
        write_output_on_error=write_output_on_error,
        created=created,
        spdxId_prefix=spdxId_prefix,
        spdxId_uuid=spdxId_uuid,
        build_type=build_type,
        build_id=build_id,
        package_license=package_license,
        package_version=package_version,
        package_copyright_text=package_copyright_text,
        prettify_json=prettify_json,
    )


def _validate_path_arguments(src_tree: PathStr, obj_tree: PathStr, root_paths: list[PathStr]) -> None:
    if not os.path.exists(src_tree):
        raise argparse.ArgumentTypeError(f"--src-tree {src_tree} does not exist")
    if not os.path.exists(obj_tree):
        raise argparse.ArgumentTypeError(f"--obj-tree {obj_tree} does not exist")
    for root_path in root_paths:
        if not os.path.exists(os.path.join(obj_tree, root_path)):
            raise argparse.ArgumentTypeError(
                f"path to root artifact {os.path.join(obj_tree, root_path)} does not exist"
            )
