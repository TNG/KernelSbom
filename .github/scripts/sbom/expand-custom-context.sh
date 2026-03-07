#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

# This script expands custom namespace prefixes to their full namespace URIs
# throughout the document and replaces the @context array with just the
# SPDX context URL.
#
# Usage:
#   ./expand-custom-context.sh [--prefix PREFIX] <spdx.json> [<spdx.json> ...]
#
# Examples:
#   # Create expanded-sbom.spdx.json (default prefix is "expanded-")
#   ./expand-custom-context.sh sbom.spdx.json

set -euo pipefail

output_prefix="expanded-"
if [[ "${1:-}" == --prefix ]]; then
    output_prefix="$2"
    shift 2
fi

spdx_documents=("$@")

for spdx_document in "${spdx_documents[@]}"; do
    # Extract SPDX context URL
    spdx_context=$(jq -r '.["@context"][0]' "$spdx_document")

    # Create a temporary sed script
    sed_script=$(mktemp)

    # Replace prefixes with full namespaces
    while IFS=$'\t' read -r prefix namespace; do
        # Escape special characters for sed
        namespace_escaped=$(printf '%s\n' "$namespace" | sed 's/[[\.*^$()+?{|]/\\&/g')
        echo "s|\"${prefix}:|\"${namespace_escaped}|g" >> "$sed_script"
    done < <(jq -r '.["@context"][1] | to_entries[] | "\(.key)\t\(.value)"' "$spdx_document")

    # Update @context and write to file
    output_file="$(dirname "$spdx_document")/${output_prefix}$(basename "$spdx_document")"
    sed -f "$sed_script" "$spdx_document" |
    jq --arg ctx "$spdx_context" '.["@context"] = $ctx' > "$output_file"

    # Clean up temporary sed script
    rm "$sed_script"
done
