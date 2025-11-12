# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from .spdxId import generate_spdx_id, set_spdx_uri_prefix
from .serialization import JsonLdDocument

__all__ = ["JsonLdDocument", "generate_spdx_id", "set_spdx_uri_prefix"]
