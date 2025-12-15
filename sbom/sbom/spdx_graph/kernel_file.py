# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
import re
from sbom.cmd_graph import CmdGraph
from sbom.path_utils import PathStr, is_relative_to
from sbom.spdx import SpdxId, SpdxIdGenerator
from sbom.spdx.core import Hash
from sbom.spdx.software import ContentIdentifier, File, SoftwarePurpose
import sbom.sbom_logging as sbom_logging
from sbom.spdx_graph.spdx_graph_model import SpdxIdGeneratorCollection


class KernelFileLocation(Enum):
    """Represents the location of a file relative to the source/object trees."""

    SOURCE_TREE = "source_tree"
    """File is located in the source tree."""
    OBJ_TREE = "obj_tree"
    """File is located in the object tree."""
    EXTERNAL = "external"
    """File is located outside both source and object trees."""
    BOTH = "both"
    """File is located in a folder that is both source and object tree."""


@dataclass
class KernelFile:
    """kernel-specific metadata used to generate an SPDX File element."""

    absolute_path: PathStr
    """Absolute path of the file."""
    file_location: KernelFileLocation
    """Location of the file relative to the source/object trees."""
    name: str
    """name of the file element. Should be relative to the source tree if file_location equals SOURCE_TREE and relative to the object tree if file_location equals OBJ_TREE. If file_location equals EXTERNAL, the absolute path is used."""
    license_identifier: str | None
    """SPDX license ID if file_location equals SOURCE_TREE or BOTH; otherwise None."""
    spdx_id_generator: SpdxIdGenerator
    """Generator for the SPDX ID of the file element."""

    _spdx_file_element: File | None = None

    @classmethod
    def create(
        cls,
        absolute_path: PathStr,
        obj_tree: PathStr,
        src_tree: PathStr,
        spdx_id_generators: SpdxIdGeneratorCollection,
        is_output: bool,
    ) -> "KernelFile":
        is_in_obj_tree = is_relative_to(absolute_path, obj_tree)
        is_in_src_tree = is_relative_to(absolute_path, src_tree)

        # file element name should be relative to output or src tree if possible
        if not is_in_src_tree and not is_in_obj_tree:
            file_element_name = str(absolute_path)
            file_location = KernelFileLocation.EXTERNAL
            spdx_id_generator = spdx_id_generators.build
        elif is_in_src_tree and src_tree == obj_tree:
            file_element_name = os.path.relpath(absolute_path, obj_tree)
            file_location = KernelFileLocation.BOTH
            spdx_id_generator = spdx_id_generators.output if is_output else spdx_id_generators.build
        elif is_in_obj_tree:
            file_element_name = os.path.relpath(absolute_path, obj_tree)
            file_location = KernelFileLocation.OBJ_TREE
            spdx_id_generator = spdx_id_generators.output if is_output else spdx_id_generators.build
        else:
            file_element_name = os.path.relpath(absolute_path, src_tree)
            file_location = KernelFileLocation.SOURCE_TREE
            spdx_id_generator = spdx_id_generators.source

        # parse spdx license identifier
        license_identifier = (
            _parse_spdx_license_identifier(absolute_path)
            if file_location == KernelFileLocation.SOURCE_TREE or file_location == KernelFileLocation.BOTH
            else None
        )

        return KernelFile(
            absolute_path,
            file_location,
            file_element_name,
            license_identifier,
            spdx_id_generator,
        )

    @property
    def spdx_file_element(self) -> File:
        if self._spdx_file_element is None:
            self._spdx_file_element = _build_file_element(
                self.absolute_path,
                self.name,
                self.spdx_id_generator.generate(),
                self.file_location,
            )
        return self._spdx_file_element


@dataclass
class KernelFileCollection:
    """Collection of kernel files."""

    source: dict[PathStr, KernelFile]
    build: dict[PathStr, KernelFile]
    output: dict[PathStr, KernelFile]

    @classmethod
    def create(
        cls, cmd_graph: CmdGraph, obj_tree: PathStr, src_tree: PathStr, spdx_id_generators: SpdxIdGeneratorCollection
    ) -> "KernelFileCollection":
        source: dict[PathStr, KernelFile] = {}
        build: dict[PathStr, KernelFile] = {}
        output: dict[PathStr, KernelFile] = {}
        root_node_paths = {node.absolute_path for node in cmd_graph.roots}
        for node in cmd_graph:
            is_root = node.absolute_path in root_node_paths
            kernel_file = KernelFile.create(node.absolute_path, obj_tree, src_tree, spdx_id_generators, is_root)
            if is_root:
                output[kernel_file.absolute_path] = kernel_file
            elif kernel_file.file_location == KernelFileLocation.SOURCE_TREE:
                source[kernel_file.absolute_path] = kernel_file
            else:
                build[kernel_file.absolute_path] = kernel_file

        return KernelFileCollection(source, build, output)

    def to_dict(self) -> dict[PathStr, KernelFile]:
        return {**self.source, **self.build, **self.output}


def _build_file_element(absolute_path: PathStr, name: str, spdx_id: SpdxId, file_location: KernelFileLocation) -> File:
    verifiedUsing: list[Hash] = []
    content_identifier: list[ContentIdentifier] = []
    if os.path.exists(absolute_path):
        verifiedUsing = [Hash(algorithm="sha256", hashValue=_sha256(absolute_path))]
        content_identifier = [
            ContentIdentifier(
                software_contentIdentifierType="gitoid", software_contentIdentifierValue=_git_blob_oid(absolute_path)
            )
        ]
    elif file_location == KernelFileLocation.EXTERNAL:
        sbom_logging.warning(
            "Cannot compute hash for {absolute_path} because file does not exist.", absolute_path=absolute_path
        )
    else:
        sbom_logging.error(
            "Cannot compute hash for {absolute_path} because file does not exist.", absolute_path=absolute_path
        )

    # primary purpose
    primary_purpose = _get_primary_purpose(absolute_path)

    return File(
        spdxId=spdx_id,
        name=name,
        verifiedUsing=verifiedUsing,
        software_primaryPurpose=primary_purpose,
        software_contentIdentifier=content_identifier,
    )


def _sha256(path: PathStr) -> str:
    """Compute the SHA-256 hash of a file."""
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


def _git_blob_oid(file_path: str) -> str:
    """
    Compute the Git blob object ID (SHA-1) for a file, like `git hash-object`.

    Args:
        file_path: Path to the file.

    Returns:
        SHA-1 hash (hex) of the Git blob object.
    """
    with open(file_path, "rb") as f:
        content = f.read()
    header = f"blob {len(content)}\0".encode()
    store = header + content
    sha1_hash = hashlib.sha1(store).hexdigest()
    return sha1_hash


# REUSE-IgnoreStart
SPDX_LICENSE_IDENTIFIER_PATTERN = re.compile(r"SPDX-License-Identifier:\s*(?P<id>.*?)(?:\s*(\*/|$))")
# REUSE-IgnoreEnd


def _parse_spdx_license_identifier(absolute_path: str, max_lines: int = 5) -> str | None:
    """
    Extracts the SPDX-License-Identifier from the first few lines of a source file.

    Args:
        absolute_path: Path to the source file.
        max_lines: Number of lines to scan from the top (default: 5).

    Returns:
        The license identifier string (e.g., 'GPL-2.0-only') if found, otherwise None.
    """
    try:
        with open(absolute_path, "r") as f:
            for _ in range(max_lines):
                match = SPDX_LICENSE_IDENTIFIER_PATTERN.search(f.readline())
                if match:
                    return match.group("id")
    except (UnicodeDecodeError, OSError):
        return None
    return None


def _get_primary_purpose(absolute_path: PathStr) -> SoftwarePurpose | None:
    def ends_with(suffixes: list[str]) -> bool:
        return any(absolute_path.endswith(suffix) for suffix in suffixes)

    def includes_path_segments(path_segments: list[str]) -> bool:
        return any(segment in absolute_path for segment in path_segments)

    # Source code
    if ends_with([".c", ".h", ".S", ".s", ".rs", ".pl"]):
        return "source"

    # Libraries
    if ends_with([".a", ".so", ".rlib"]):
        return "library"

    # Archives
    if ends_with([".xz", ".cpio", ".gz", ".tar", ".zip"]):
        return "archive"

    # Applications
    if ends_with(["bzImage", "Image"]):
        return "application"

    # Executables / machine code
    if ends_with([".bin", ".elf", "vmlinux", "vmlinux.unstripped", "bpfilter_umh"]):
        return "executable"

    # Kernel modules
    if ends_with([".ko"]):
        return "module"

    # Data files
    if ends_with(
        [
            ".tbl",
            ".relocs",
            ".rmeta",
            ".in",
            ".dbg",
            ".x509",
            ".pbm",
            ".ppm",
            ".dtb",
            ".uc",
            ".inc",
            ".dts",
            ".dtsi",
            ".dtbo",
            ".xml",
            ".ro",
            "initramfs_inc_data",
            "default_cpio_list",
            "x509_certificate_list",
            "utf8data.c_shipped",
            "blacklist_hash_list",
            "x509_revocation_list",
            "cpucaps",
            "sysreg",
        ]
    ) or includes_path_segments(["drivers/gpu/drm/radeon/reg_srcs/"]):
        return "data"

    # Configuration files
    if ends_with([".pem", ".key", ".conf", ".config", ".cfg", ".bconf"]):
        return "configuration"

    # Documentation
    if ends_with([".md"]):
        return "documentation"

    # Other / miscellaneous
    if ends_with([".o", ".tmp"]):
        return "other"

    sbom_logging.warning("Could not infer primary purpose for {absolute_path}", absolute_path=absolute_path)
