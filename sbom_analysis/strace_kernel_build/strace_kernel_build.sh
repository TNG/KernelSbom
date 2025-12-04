# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#!/usr/bin/env bash
set -euo pipefail

SRC_TREE="../../../linux.v6.17.tinyconfig.x86"  # relative to script root
OBJ_TREE="kernel_build"                         # relative to src tree
SBOM_USED_FILES="../../sbom.used-files.txt"      # relative to script root

[ $# -ge 1 ] && SRC_TREE="$1"
[ $# -ge 2 ] && OBJ_TREE="$2"

STRACE_LOG="strace.log" # Full strace log capturing all file access (open/openat) during the kernel build.
FILES_TOUCHED="files_touched.txt" # Unique list of all files the kernel build process attempted to open, extracted from the strace log.
SOURCE_FILES="source_files_touched.txt" # Subset of FILES_TOUCHED that are actual source files inside the source tree
FILTERED_SOURCE_FILES="filtered_source_files_touched.txt" # Subset of SOURCE_FILES, excluding build system files not tracked by the cmd graph
STRACE_ONLY="strace_only.txt" # Subset of FILTERED_SOURCE_FILES, excluding the files that are found in the cmd graph
SBOM_USED_FILES_ONLY="sbom_used_files_only.txt" # Subset of SBOM_USED_FILES, excluding the files that are found in strace

# Absolute paths
SCRIPT_DIR=$(dirname "$(realpath "$0")")
SRC_TREE_ABSOLUTE=$(realpath "$SCRIPT_DIR/$SRC_TREE")
OBJ_TREE_ABSOLUTE=$(realpath "$SRC_TREE_ABSOLUTE/$OBJ_TREE")
SBOM_USED_FILES_ABSOLUTE=$(realpath "$SCRIPT_DIR/$SBOM_USED_FILES")

STRACE_LOG_ABSOLUTE="$SCRIPT_DIR/$STRACE_LOG" 
FILES_TOUCHED_ABSOLUTE="$SCRIPT_DIR/$FILES_TOUCHED" 
SOURCE_FILES_ABSOLUTE="$SCRIPT_DIR/$SOURCE_FILES" 
FILTERED_SOURCE_FILES_ABSOLUTE="$SCRIPT_DIR/$FILTERED_SOURCE_FILES"
STRACE_ONLY_ABSOLUTE="$SCRIPT_DIR/$STRACE_ONLY"
SBOM_USED_FILES_ONLY_ABSOLUTE="$SCRIPT_DIR/$SBOM_USED_FILES_ONLY"

# Run the kernel build with strace
cd "$SRC_TREE_ABSOLUTE"
strace -f -e trace=file -o "$STRACE_LOG_ABSOLUTE" \
    make -j"$(nproc)" O="$OBJ_TREE_ABSOLUTE"

# Extract filenames from strace log
awk -F\" '/open(at)?\(/ {print $2}' "$STRACE_LOG_ABSOLUTE" \
    | sort -u \
    > "$FILES_TOUCHED_ABSOLUTE"

echo "Files touched: $(wc -l < "$FILES_TOUCHED_ABSOLUTE")"


# Filter source files
while read -r f; do
    # file paths are either relative to the OBJ_TREE or absolute. Convert all paths to absolute ones.
    if [[ "$f" != /* ]]; then
        f="$OBJ_TREE_ABSOLUTE/$f"
    fi

    if [[ ! -f "$f" ]]; then
        continue
    fi

    f=$(realpath "$f")

    # if $f lies in the src tree and not in the output tree then it is a valid source file
    if [[ "$f" == "$SRC_TREE_ABSOLUTE/"* && "$f" != "$OBJ_TREE_ABSOLUTE/"* ]]; then
        echo "$f"
    fi
done < "$FILES_TOUCHED_ABSOLUTE" >| "$SOURCE_FILES_ABSOLUTE"
sort -u "$SOURCE_FILES_ABSOLUTE" -o "$SOURCE_FILES_ABSOLUTE"
echo "Source files touched: $(wc -l < "$SOURCE_FILES_ABSOLUTE")"


# Filter out files not considered in cmd graph
while read -r f; do
    basename=$(basename "$f")
    if [[ "$basename" == Kbuild* || "$basename" == Makefile* || "$basename" == Kconfig* ]]; then
        continue
    fi

    f="${f#$SRC_TREE_ABSOLUTE/}"

    if [[ "$f" == "tools/"* || "$f" == "scripts/"* || "$f" == ".git/"* ]]; then
        continue
    fi

    echo "$f"
done < "$SOURCE_FILES_ABSOLUTE" >| "$FILTERED_SOURCE_FILES_ABSOLUTE"
sort -u $FILTERED_SOURCE_FILES_ABSOLUTE -o $FILTERED_SOURCE_FILES_ABSOLUTE
echo "Filtered source files touched: $(wc -l < "$FILTERED_SOURCE_FILES_ABSOLUTE")"


# Compare strace files with sbom.used-files.txt generated from the cmd graph
sorted_sbom_used_files=$(sort "$SBOM_USED_FILES_ABSOLUTE")

comm -23 "$FILTERED_SOURCE_FILES_ABSOLUTE" <(sort "$SBOM_USED_FILES_ABSOLUTE") >| "$STRACE_ONLY_ABSOLUTE"
comm -13 "$FILTERED_SOURCE_FILES_ABSOLUTE" <(sort "$SBOM_USED_FILES_ABSOLUTE") >| "$SBOM_USED_FILES_ONLY_ABSOLUTE"

echo "Files in strace but not in cmd graph: $(wc -l < $STRACE_ONLY_ABSOLUTE)"
echo "Files in sbom.used-files but not in strace: $(wc -l < $SBOM_USED_FILES_ONLY_ABSOLUTE)"
