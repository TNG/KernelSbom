# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from itertools import count
import uuid

SpdxId = str
_spdx_uri_prefix = "https://spdx.org/spdxdocs/"
_uuid = uuid.uuid4()
_counter = count(0)

_generated_ids: dict[str, int] = {}


def set_spdx_uri_prefix(prefix: str) -> None:
    global _spdx_uri_prefix
    _spdx_uri_prefix = prefix


def generate_spdx_id(object_type: str, object_suffix: str | None = None) -> SpdxId:
    if object_suffix is None:
        object_suffix = f"gnrtd{next(_counter)}"
    spdxId = f"{_spdx_uri_prefix}{_uuid}/{object_type}#{object_suffix}"

    # compare spdxIds case-insensitively and deduplicate if needed
    spdxId_lower = spdxId.lower()
    if spdxId_lower in _generated_ids:
        _generated_ids[spdxId_lower] += 1
        spdxId += f"-{_generated_ids[spdxId_lower]}"
    else:
        _generated_ids[spdxId_lower] = 0

    return spdxId
