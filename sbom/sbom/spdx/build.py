# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass, field
from sbom.spdx.core import DictionaryEntry, Element, Hash


@dataclass(kw_only=True)
class Build(Element):
    type: str = field(init=False, default="build_Build")
    build_buildType: str
    build_buildId: str
    build_environment: list[DictionaryEntry] = field(default_factory=list[DictionaryEntry])
    build_configSourceUri: list[str] = field(default_factory=list[str])
    build_configSourceDigest: list[Hash] = field(default_factory=list[Hash])
