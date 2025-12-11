#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

set -euo pipefail

spdx_documents=("$@")

# Install spdx-tools-java
export SPDX_TOOLS_VERSION=2.0.2
if [[ ! -f "tools-java-${SPDX_TOOLS_VERSION}-jar-with-dependencies.jar" ]]; then
    echo "Download spdx-tools-java"
    curl -sLO "https://github.com/spdx/tools-java/releases/download/v${SPDX_TOOLS_VERSION}/tools-java-${SPDX_TOOLS_VERSION}.zip"
    unzip -j "tools-java-${SPDX_TOOLS_VERSION}.zip" "tools-java-${SPDX_TOOLS_VERSION}-jar-with-dependencies.jar"
    rm "tools-java-${SPDX_TOOLS_VERSION}.zip"
fi

max_size=$((500 * 1024 * 1024)) # 500MB
for spdx_document in "${spdx_documents[@]}"; do
    filesize=$(stat -c%s "$spdx_document")
    if [[ $filesize -gt $max_size ]]; then
        echo "Skipping SPDX validation for $spdx_document because the file is too large ($((filesize/1024/1024)) MB)"
        continue
    fi

    filesize=$(stat -c%s "$spdx_document")
    java -Xmx15G -Xms12G -jar "tools-java-${SPDX_TOOLS_VERSION}-jar-with-dependencies.jar" Verify "$spdx_document"
done
