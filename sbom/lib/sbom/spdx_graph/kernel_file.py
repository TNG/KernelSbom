# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass
import hashlib
import logging
import os
import re
from typing import Any, Literal
from sbom.path_utils import PathStr, is_relative_to
from sbom.spdx.core import Hash
from sbom.spdx.software import File
import sbom.errors as sbom_errors
from sbom.spdx import generate_spdx_id


@dataclass(kw_only=True)
class KernelFile(File):
    """SPDX file element with kernel-specific metadata."""

    absolute_path: PathStr
    """Absolute file system path."""

    tree: Literal["src_tree", "output_tree"] | None
    """File location: source tree, output tree, or external."""

    license_identifier: str | None
    """SPDX license ID if from source tree; otherwise None."""

    def to_dict(self) -> dict[str, Any]:
        d = super().to_dict()
        d.pop("absolute_path", None)
        d.pop("tree", None)
        d.pop("license_identifier", None)
        return d


def build_kernel_file_element(absolute_path: PathStr, output_tree: PathStr, src_tree: PathStr) -> KernelFile:
    is_in_output_tree = is_relative_to(absolute_path, output_tree)
    is_in_src_tree = is_relative_to(absolute_path, src_tree)

    # file element name should be relative to output or src tree if possible
    if is_in_output_tree:
        file_element_name = os.path.relpath(absolute_path, output_tree)
        tree = "output_tree"
    elif is_in_src_tree:
        file_element_name = os.path.relpath(absolute_path, src_tree)
        tree = "src_tree"
    else:
        file_element_name = str(absolute_path)
        tree = None

    # Create file hash if possible. Hashes for files outside the src and output trees are optional.
    verifiedUsing: list[Hash] = []
    if os.path.exists(absolute_path):
        verifiedUsing = [Hash(algorithm="sha256", hashValue=_sha256(absolute_path))]
    elif is_in_output_tree or is_in_src_tree:
        sbom_errors.log(f"Cannot compute hash for {absolute_path} because file does not exist.")
    else:
        logging.warning(f"Cannot compute hash for {absolute_path} because file does not exist.")

    # parse spdx license identifier
    license_identifier = _parse_spdx_license_identifier(absolute_path) if tree == "src_tree" else None

    file_element = KernelFile(
        spdxId=generate_spdx_id("software_File", file_element_name),
        name=file_element_name,
        verifiedUsing=verifiedUsing,
        absolute_path=absolute_path,
        tree=tree,
        license_identifier=license_identifier,
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
