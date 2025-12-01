#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

set -euo pipefail

spdx_documents=("$@")

export SPDX_TOOLS_VERSION=2.0.2
if [[ ! -f "tools-java-${SPDX_TOOLS_VERSION}-jar-with-dependencies.jar" ]]; then
    echo "Download spdx-tools-java"
    curl -sLO "https://github.com/spdx/tools-java/releases/download/v${SPDX_TOOLS_VERSION}/tools-java-${SPDX_TOOLS_VERSION}.zip"
    unzip -j "tools-java-${SPDX_TOOLS_VERSION}.zip" "tools-java-${SPDX_TOOLS_VERSION}-jar-with-dependencies.jar"
    rm "tools-java-${SPDX_TOOLS_VERSION}.zip"
fi


npm install -g jsonld-cli --silent
if [[ ! -f "fixed-spdx-context.jsonld" ]]; then
    # The spdx-context.jsonld is broken (https://github.com/spdx/spdx-spec/issues/1307). 
    # To properly expand/compact the document we must fix the context on our end.
    echo "Download and fix spdx-context.jsonld"
    curl -sLO https://spdx.org/rdf/3.0.1/spdx-context.jsonld
    jq '
    # Remove the "@type": "@vocab" key-value pairs from object valued properties because these break compaction
    (.["@context"].verifiedUsing) |= del(.["@type"]) |
    (.["@context"].software_contentIdentifier) |= del(.["@type"]) |
    (.["@context"].import) |= del(.["@type"]) |
    (.["@context"].build_configSourceDigest) |= del(.["@type"]) |
    (.["@context"].build_environment) |= del(.["@type"])
    |
    # Add "@container": "@set" to array properties to make values always be compacted as arrays
    (.["@context"].rootElement) |= (. + {"@container": "@set"}) |
    (.["@context"].verifiedUsing) |= (. + {"@container": "@set"}) |
    (.["@context"].software_contentIdentifier) |= (. + {"@container": "@set"}) |
    (.["@context"].import) |= (. + {"@container": "@set"}) |
    (.["@context"].to) |= (. + {"@container": "@set"}) |
    (.["@context"].createdBy) |= (. + {"@container": "@set"}) |
    (.["@context"].software_sbomType) |= (. + {"@container": "@set"}) |
    (.["@context"].originatedBy) |= (. + {"@container": "@set"}) |
    (.["@context"].build_environment) |= (. + {"@container": "@set"})
    ' spdx-context.jsonld > fixed-spdx-context.jsonld
    rm spdx-context.jsonld
fi

expand_context() {
    local spdx_document="$1"
    
    # Expand custom context
    export NODE_OPTIONS="--max-old-space-size=12288"
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
    rm expanded-sbom.spdx.json

    # Re-insert the reference to the original spdx context
    sed -i 's#fixed-spdx-context.jsonld#https://spdx.org/rdf/3.0.1/spdx-context.jsonld#g' fixed-sbom.spdx.json

    # overwrite the original spdx document
    mv fixed-sbom.spdx.json $spdx_document
}

max_size=$((100 * 1024 * 1024)) # 100MB
for sbom in "${spdx_documents[@]}"; do
    filesize=$(stat -c%s "$sbom")
    if [[ $filesize -gt $max_size ]]; then
        echo "Skipping SPDX validation for $sbom because the file is too large ($((filesize/1024/1024)) MB)"
        continue
    fi
    echo "Expand custom context for $sbom (size: $((filesize/1024/1024)) MB)"
    expand_context "$sbom"

    filesize=$(stat -c%s "$sbom")
    echo "Validate expanded $sbom (size: $((filesize/1024/1024)) MB)"
    java -Xmx15G -Xms12G -jar "tools-java-${SPDX_TOOLS_VERSION}-jar-with-dependencies.jar" Verify "$sbom"
done
