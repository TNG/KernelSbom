# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass, field
from sbom.spdx.core import Element


@dataclass(kw_only=True)
class Build(Element):
    type: str = field(init=False, default="build_Build")
    build_buildType: str
