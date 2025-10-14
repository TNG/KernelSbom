<!--
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
-->

# CMD Graph Visualization

The [`main.py`](./main.py) script visualizes cmd graphs using the [force-graph](https://github.com/vasturiano/force-graph) library.

![force-graph](./vmlinux-no-headers-no-configs.png)

To view the interactive force graphs:

1. Generate graph data by running the script:
    ```bash
    cd sbom_analysis/cmd_graph_visualization
    python main.py
    ```
    This will create `cmd_graph.json` graph data within the `web/` directory.
    > **Note:** The script assumes that the `linux` source tree lies next to this repository. You get this layout by following the [Getting Started](../../README.md#getting-started) section.
2. Start a simple HTTP server to serve the [index.html](web/index.html)
    ```bash
    cd web
    python -m http.server 8000
    ```
3. Open your web browser and navigate to [http://localhost:8000](http://localhost:8000) to interact with the force graphs.
