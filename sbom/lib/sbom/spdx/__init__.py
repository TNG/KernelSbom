# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from .spdxId import SpdxId, SpdxIdGenerator
from .serialization import JsonLdDocument

__all__ = ["JsonLdDocument", "SpdxId", "SpdxIdGenerator"]
