# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass, field
from sbom.spdx.core import Element
from sbom.spdx.spdxId import SpdxId, generate_spdx_id


@dataclass(kw_only=True)
class Build(Element):
    type: str = field(init=False, default="build_Build")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("build_Build"))
    build_buildType: str
