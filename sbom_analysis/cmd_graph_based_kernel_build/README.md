<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

# CMD Graph-Based Kernel Build

The script [`cmd_graph_based_kernel_build.py`](./cmd_graph_based_kernel_build.py) validates the completeness of the command graph — i.e., whether it includes all source files required to build the Linux kernel.

It does this by reconstructing a minimal Linux source tree under `linux-cmd/`. The script copies the original `linux` source tree and removes any source files **not** referenced in the command graph. If the kernel builds successfully from this pruned tree, it confirms that the command graph includes all necessary files.

To run the validation:

```bash
python sbom_analysis/cmd_graph_based_kernel_build/cmd_graph_based_kernel_build.py
cd linux-cmd
make defconfig O=kernel-build
make -j$(nproc) O=kernel-build
```
> **Note:** The script assumes that the `linux` source tree lies within this repository. You get this layout by default when using the [devcontainer](../.devcontainer/devcontainer.json).
