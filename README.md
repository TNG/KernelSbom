<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

# KernelSbom

A script to generate an SPDX-format Software Bill of Materials (SBOM) for the `vmlinux` kernel build.
The eventual goal is to integrate the `sbom/` directory into the `linux/scripts/` directory in the official [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/) kernel source tree.

## Getting Started
1. Clone the repository
2. Activate the venv and install build dependencies
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install pre-commit reuse ruff
    pre-commit install
    ```
3. provide a linux src and output tree, e.g., by downloading precompiled testdata from [KernelSbom-TestData](https://fileshare.tngtech.com/library/98e7e6f8-bffe-4a55-a8d2-817d4f3e51e8/KernelSbom-TestData/)
    ```bash
    test_archive="linux-defconfig.tar.gz"
    curl -L -o "$test_archive" "https://fileshare.tngtech.com/d/e69946da808b41f88047/files/?p=%2F$test_archive&dl=1"
    tar -xzf "$test_archive"
    rm "$test_archive"
    ```
    or cloning the [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) repo and building your own config
    ```bash
    git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
    cd linux
    make <config> O=kernel_build
    make -j$(nproc) O=kernel_build
    ```
4. Run the [sbom.py](sbom/sbom.py) script
    ```bash
    python3 sbom/sbom.py \
      --src-tree linux \
      --output-tree linux/kernel_build \
      --root-output-in-tree vmlinux \
      --spdx sbom.spdx.json \
      --used-files sbom.used_files.txt
    ```
    Starting from `vmlinux` the script builds the **cmd graph**, a directed acyclic graph (DAG) where nodes are filenames and edges represent build dependencies extracted from `.<filename>.cmd` files. Based on the cmd graph, the final `sbom.spdx.json`, `sbom.used_files.txt` files are created and saved in this repository’s root directory.

## Directory Structure

- `sbom/`
  - [sbom.py](sbom/sbom.py) - The main script responsible for generating the SBOM.
  - `sbom/lib/sbom` - Library modules used by the main script.
  - `sbom/lib/sbom_tests` - Unit tests for the library modules.
- `sbom_analysis` - Additional scripts for analyzing the outputs produced by the main script.
  - [sbom_analysis/cmd_graph_based_kernel_build](sbom_analysis/cmd_graph_based_kernel_build/README.md) - Validation of cmd graph completeness by rebuilding the linux kernel only with files referenced in the cmd graph.
  - [sbom_analysis/cmd_graph_visualization](sbom_analysis/cmd_graph_visualization/README.md) - Interactive visualization of the cmd graph
- `testdata_generation` - Describes how the precompiled kernel builds in [KernelSbom-TestData](https://fileshare.tngtech.com/library/98e7e6f8-bffe-4a55-a8d2-817d4f3e51e8/KernelSbom-TestData/) were generated.

The main contribution is the content of the `sbom` directory which eventually should be moved into the `linux/scripts/` directory in the official [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/) kernel source tree.

## Reuse

when commiting `reuse lint` is executed as a pre-commit hook to check if all files have compliant License headers. If any file is missing a license header add it via 
```
reuse annotate --license="GPL-2.0-only" --copyright="TNG Technology Consulting GmbH" <filename>
```
