<!--
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
-->

# CMD Graph-Based Kernel Build

The script [`cmd_graph_based_kernel_build.py`](./cmd_graph_based_kernel_build.py) validates the completeness of the cmd graph — i.e., whether it includes all source files required to build the Linux kernel.

It does this by reconstructing a minimal Linux source tree under `linux_cmd/`. The script copies the original `linux` source tree and removes any source files **not** referenced in the cmd graph. If the kernel builds successfully from this pruned tree, it confirms that the cmd graph includes all necessary files.

To run the validation:

```bash
python sbom_analysis/cmd_graph_based_kernel_build/cmd_graph_based_kernel_build.py
cd linux_cmd
make defconfig O=kernel_build
make -j$(nproc) O=kernel_build
```
> **Note:** The script assumes that the `linux` source tree lies within this repository. You get this layout by default when using the [devcontainer](../.devcontainer/devcontainer.json).
