# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass, field
from sbom.spdx.core import DictionaryEntry, Element, Hash


@dataclass(kw_only=True)
class Build(Element):
    type: str = field(init=False, default="build_Build")
    build_buildType: str
    build_buildId: str
    build_environment: list[DictionaryEntry] = field(default_factory=list[DictionaryEntry])
    build_configSourceUri: str | None = None
    build_configSourceDigest: Hash | None = None
