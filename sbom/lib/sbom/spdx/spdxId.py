# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from itertools import count
import uuid

SpdxId = str
_spdx_uri_prefix = "https://kernel.org/"
_uuid = uuid.uuid4()
_counter = count(0)


def set_spdx_uri_prefix(prefix: str) -> None:
    global _spdx_uri_prefix
    _spdx_uri_prefix = prefix


def generate_spdx_id(object_type: str, object_suffix: str | None = None) -> SpdxId:
    if object_suffix is None:
        object_suffix = f"gnrtd{next(_counter)}"
    return f"{_spdx_uri_prefix}{_uuid}/{object_type}#{object_suffix}"
