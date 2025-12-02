# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
from enum import Enum
import hashlib
import os
import re
from typing import Any
from sbom.path_utils import PathStr, is_relative_to
from sbom.spdx.core import Hash
from sbom.spdx.software import ContentIdentifier, File, SoftwarePurpose
import sbom.sbom_logging as sbom_logging
from sbom.spdx.spdxId import SpdxIdGenerator


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


@dataclass(kw_only=True)
class KernelFile(File):
    """SPDX file element with kernel-specific metadata."""

    absolute_path: PathStr
    file_location: KernelFileLocation
    license_identifier: str | None
    """SPDX license ID if file_location equals SOURCE or BOTH; otherwise None."""

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.pop("absolute_path", None)
        d.pop("file_location", None)
        d.pop("license_identifier", None)
        return d


def build_kernel_file_element(
    absolute_path: PathStr,
    obj_tree: PathStr,
    src_tree: PathStr,
    source_id_generator: SpdxIdGenerator,
    build_id_generator: SpdxIdGenerator,
) -> KernelFile:
    is_in_obj_tree = is_relative_to(absolute_path, obj_tree)
    is_in_src_tree = is_relative_to(absolute_path, src_tree)

    # file element name should be relative to output or src tree if possible
    if not is_in_src_tree and not is_in_obj_tree:
        file_element_name = str(absolute_path)
        file_location = KernelFileLocation.EXTERNAL
    elif is_in_src_tree and src_tree == obj_tree:
        file_element_name = os.path.relpath(absolute_path, obj_tree)
        file_location = KernelFileLocation.BOTH
    elif is_in_obj_tree:
        file_element_name = os.path.relpath(absolute_path, obj_tree)
        file_location = KernelFileLocation.OBJ_TREE
    else:
        file_element_name = os.path.relpath(absolute_path, src_tree)
        file_location = KernelFileLocation.SOURCE_TREE

    # Create file hash if possible. Hashes for files outside the src and object trees are optional.
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

    # parse spdx license identifier
    license_identifier = (
        _parse_spdx_license_identifier(absolute_path)
        if file_location == KernelFileLocation.SOURCE_TREE or file_location == KernelFileLocation.BOTH
        else None
    )

    # primary purpose
    primary_purpose = _get_primary_purpose(absolute_path)

    # spdxId
    spdxId = (
        source_id_generator.generate()
        if file_location == KernelFileLocation.SOURCE_TREE
        else build_id_generator.generate()
    )

    return KernelFile(
        spdxId=spdxId,
        name=file_element_name,
        verifiedUsing=verifiedUsing,
        absolute_path=absolute_path,
        file_location=file_location,
        license_identifier=license_identifier,
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
    if ends_with(["bzImage"]):
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
