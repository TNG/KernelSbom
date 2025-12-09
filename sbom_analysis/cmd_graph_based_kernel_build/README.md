<!--
SPDX-License-Identifier: GPL-2.0-only OR MIT
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
-->

# CMD Graph-Based Kernel Build

The [`main.py`](./main.py) script validates the completeness of the cmd graph — i.e., whether it includes all source files required to build the Linux kernel.

It does this by reconstructing a minimal Linux source tree under `linux_cmd/`. The script copies the original `linux` source tree and removes any source files **not** referenced in the cmd graph. If the kernel builds successfully from this pruned tree, it confirms that the cmd graph includes all necessary files.
If not the script automatically tries to find additional missing files based on the make error of the build attempt and adds those missing files as well. Then it retries to build the kernel. All additionally added files are stored in `missing_sources_in_cmd_graph.json`. 
Outputs for different configs are stored in the `missing_sources/` directory. 

## Example
```bash
# Optionally copy over a pregenerated missing_sources file, e.g., for the tinyconfig
cd sbom_analysis/cmd_graph_based_kernel_build
cp missing_sources/missing_sources_in_cmd_graph.linux.v6.17.tinyconfig.json missing_sources_in_cmd_graph.json 

python main.py
```
> **Note:** The script assumes that the `linux` source tree lies next to this repository. You get this layout by following the [Getting Started](../../README.md#getting-started) section.
