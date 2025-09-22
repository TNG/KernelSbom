<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

# SBOM Analysis

This directory contains scripts to analyze the **cmd graph** created by the main [`sbom`](../sbom) project.

> 💡 **Note:** The scripts assume that the `linux` source tree is located next to this repository. This is the default layout when using the [devcontainer](../.devcontainer/devcontainer.json).


## Build Kernel Based on Cmd Graph

The script [`cmd_graph_based_kernel_build.py`](./cmd_graph_based_kernel_build.py) allows you to verify whether the cmd graph is complete — i.e., it includes all necessary source files required to build the kernel.

This script reconstructs a minimal Linux source tree in `linux-cmd/` by copying only the files referenced in the cmd graph from the original `linux` source tree. If the kernel builds successfully, this confirms that no required file is missing from the cmd graph.

```bash
python sbom_analysis/cmd_graph_based_kernel_build.py
cd linux-cmd
make defconfig O=kernel-build
make -j$(nproc) O=kernel-build
```

## Visualization Cmd Graph

The script [`cmd_graph_visualization.py`](./cmd_graph_visualization.py) saves the cmd graph as a [web/cmd_graph.json](./web/cmd_graph.json) file such that it can be visualized with [force-graph](https://github.com/vasturiano/force-graph) in the [web/index.html](web/index.html).

```bash
python sbom_analysis/cmd_graph_visualization.py
cd sbom_analysis/web
python -m http.server 8000
```
