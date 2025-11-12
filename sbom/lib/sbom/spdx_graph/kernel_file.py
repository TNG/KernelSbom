# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
from enum import Enum
import hashlib
import logging
import os
import re
from typing import Any
from sbom.path_utils import PathStr, is_relative_to
from sbom.spdx.core import Hash
from sbom.spdx.software import File, SoftwarePurpose
import sbom.errors as sbom_errors
from sbom.spdx import generate_spdx_id


class KernelFileLocation(Enum):
    """Represents the location of a file relative to the source/output trees."""

    SOURCE_TREE = "source_tree"
    """File is located in the source tree."""
    OUTPUT_TREE = "output_tree"
    """File is located in the output tree."""
    EXTERNAL = "external"
    """File is located outside both source and output trees."""
    BOTH = "both"
    """File is located in a folder that is both source and output tree."""


@dataclass(kw_only=True)
class KernelFile(File):
    """SPDX file element with kernel-specific metadata."""

    absolute_path: PathStr
    file_location: KernelFileLocation
    license_identifier: str | None
    """SPDX license ID if file_location equals SOURCE; otherwise None."""

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.pop("absolute_path", None)
        d.pop("file_location", None)
        d.pop("license_identifier", None)
        return d


def build_kernel_file_element(absolute_path: PathStr, output_tree: PathStr, src_tree: PathStr) -> KernelFile:
    is_in_output_tree = is_relative_to(absolute_path, output_tree)
    is_in_src_tree = is_relative_to(absolute_path, src_tree)

    # file element name should be relative to output or src tree if possible
    if not is_in_src_tree and not is_in_output_tree:
        file_element_name = str(absolute_path)
        file_location = KernelFileLocation.EXTERNAL
    elif src_tree == output_tree:
        file_element_name = os.path.relpath(absolute_path, output_tree)
        file_location = KernelFileLocation.BOTH
    elif is_in_output_tree:
        file_element_name = os.path.relpath(absolute_path, output_tree)
        file_location = KernelFileLocation.OUTPUT_TREE
    else:
        file_element_name = os.path.relpath(absolute_path, src_tree)
        file_location = KernelFileLocation.SOURCE_TREE

    # Create file hash if possible. Hashes for files outside the src and output trees are optional.
    verifiedUsing: list[Hash] = []
    if os.path.exists(absolute_path):
        verifiedUsing = [Hash(algorithm="sha256", hashValue=_sha256(absolute_path))]
    elif is_in_output_tree or is_in_src_tree:
        sbom_errors.log(f"Cannot compute hash for {absolute_path} because file does not exist.")
    else:
        logging.warning(f"Cannot compute hash for {absolute_path} because file does not exist.")

    # parse spdx license identifier
    license_identifier = (
        _parse_spdx_license_identifier(absolute_path) if file_location == KernelFileLocation.SOURCE_TREE else None
    )

    # primary purpose
    primary_purpose = _primary_purpose(absolute_path, file_location)

    file_element = KernelFile(
        spdxId=generate_spdx_id("software_File", file_element_name),
        name=file_element_name,
        verifiedUsing=verifiedUsing,
        absolute_path=absolute_path,
        file_location=file_location,
        license_identifier=license_identifier,
        software_primaryPurpose=primary_purpose,
    )

    return file_element


def _sha256(path: PathStr) -> str:
    """Compute the SHA-256 hash of a file."""
    with open(path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()


SPDX_LICENSE_IDENTIFIER_PATTERN = re.compile(
    r"SPDX-License-Identifier:\s*(?P<id>[^\s]+(?:\s+(?:AND|OR|WITH)\s+[^\s]+)*)",
    re.IGNORECASE,
)


def _parse_spdx_license_identifier(absolute_path: str, max_lines: int = 5) -> str | None:
    """
    Extracts the SPDX-License-Identifier from the first few lines of a source file.

    Args:
        absolute_path: Path to the source file.
        max_lines: Number of lines to scan from the top (default: 5).

    Returns:
        The license identifier string (e.g., 'GPL-2.0-only') if found, otherwise None.
    """
    with open(absolute_path, "r") as f:
        for _ in range(max_lines):
            match = SPDX_LICENSE_IDENTIFIER_PATTERN.search(f.readline())
            if match:
                return match.group("id")
    return None


def _primary_purpose(absolute_path: PathStr, file_location: KernelFileLocation) -> SoftwarePurpose | None:
    def endswith(suffixes: list[str]):
        return any(absolute_path.endswith(suffix) for suffix in suffixes)

    if endswith([".c", ".h", ".S", ".s", ".rs"]):
        return "source" if file_location == KernelFileLocation.SOURCE_TREE else "other"
    if endswith([".a", ".so"]):
        return "library"
    if endswith([".xz", ".cpio", ".gz"]):
        return "archive"
    if endswith([".o", ".x509"]):
        return "other"
    if endswith([".bin", ".elf", "vmlinux", "bzImage", "vmlinux.unstripped", ".dbg"]):
        return "file"
    if endswith([".tbl", ".relocs", ".rmeta", "initramfs_inc_data", "default_cpio_list", "x509_certificate_list"]):
        return "data"
    if endswith([".ko"]):
        return "module"
    return
