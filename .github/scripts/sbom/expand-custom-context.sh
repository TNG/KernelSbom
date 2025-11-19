#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

set -euo pipefail

spdx_document=$1

npm install -g jsonld-cli
curl -LO https://spdx.org/rdf/3.0.1/spdx-context.jsonld

# The spdx-context.jsonld is broken (https://github.com/spdx/spdx-spec/issues/1307). 
# To properly expand/compact the document we must fix the context on our end.
jq '
# Remove the "@type": "@vocab" key-value pairs from object valued properties because these break compaction
(.["@context"].verifiedUsing) |= del(.["@type"]) |
(.["@context"].software_contentIdentifier) |= del(.["@type"])
|
# Add "@container": "@set" to array properties to make values always be compacted as arrays
(.["@context"].rootElement) |= (. + {"@container": "@set"}) |
(.["@context"].verifiedUsing) |= (. + {"@container": "@set"}) |
(.["@context"].software_contentIdentifier) |= (. + {"@container": "@set"}) |
(.["@context"].to) |= (. + {"@container": "@set"}) |
(.["@context"].createdBy) |= (. + {"@container": "@set"}) |
(.["@context"].software_sbomType) |= (. + {"@container": "@set"}) |
(.["@context"].originatedBy) |= (. + {"@container": "@set"}) 
' spdx-context.jsonld > fixed-spdx-context.jsonld

# Expand custom context
jsonld expand $spdx_document | jsonld compact - -c "fixed-spdx-context.jsonld" > expanded-sbom.spdx.json

# Expanding and compacting the context replaces @id with spdxId which must be reverted manually
jq '
# Replace 'spdxId' for the CreationInfo with '@id'
.["@graph"] |= map(
    if (.type == "CreationInfo") and has("spdxId") then
    .["@id"] = .spdxId | del(.spdxId)
    else
    .
    end
)
' expanded-sbom.spdx.json > fixed-sbom.spdx.json

# Re-insert the reference to the original spdx context
sed -i 's#fixed-spdx-context.jsonld#https://spdx.org/rdf/3.0.1/spdx-context.jsonld#g' fixed-sbom.spdx.json

# overwrite the original spdx document
mv fixed-sbom.spdx.json $spdx_document
