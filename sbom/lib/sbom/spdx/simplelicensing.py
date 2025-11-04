# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from dataclasses import dataclass, field
from sbom.spdx.core import Element
from sbom.spdx.spdxId import SpdxId, generate_spdx_id


@dataclass(kw_only=True)
class AnyLicenseInfo(Element):
    type: str = field(init=False, default="simplelicensing_AnyLicenseInfo")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("simplelicensing_AnyLicenseInfo"))


@dataclass(kw_only=True)
class LicenseExpression(AnyLicenseInfo):
    type: str = field(init=False, default="simplelicensing_LicenseExpression")
    spdxId: SpdxId = field(default_factory=lambda: generate_spdx_id("simplelicensing_LicenseExpression"))
    simplelicensing_licenseExpression: str
