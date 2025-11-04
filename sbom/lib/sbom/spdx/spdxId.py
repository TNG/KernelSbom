# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from itertools import count
import uuid

SpdxId = str
_spdx_uri_prefix = "https://spdx.org/spdxdocs/"
_uuid = uuid.uuid4()
_counter = count(0)


def set_spdx_uri_prefix(prefix: str) -> None:
    global _spdx_uri_prefix
    _spdx_uri_prefix = prefix


def generate_spdx_id(entity_type: str, entity_suffix: str | None = None) -> SpdxId:
    if entity_suffix is None:
        entity_suffix = f"gnrtd{next(_counter)}"
    return f"{_spdx_uri_prefix}{_uuid}/{entity_type}#{entity_suffix}"
