<!--
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
-->

# CMD Graph Visualization

The script [`cmd_graph_visualization.py`](./cmd_graph_visualization.py) visualizes the cmd graph with the [force-graph](https://github.com/vasturiano/force-graph) library.

![force-graph](./vmlinux-no-headers-no-configs.png)

To view the interactive force graph:

1. Generate the graph data by running the script:
    ```bash
    cd sbom_analysis/cmd_graph_visualization
    python cmd_graph_visualization.py
    ```
    This will create the file [`web/cmd_graph.json.gz`](./web/cmd_graph.json.gz), which contains the data for the visualization.
    > **Note:** The script assumes that the `linux` source tree lies within this repository. You get this layout by default when using the [devcontainer](../.devcontainer/devcontainer.json).
2. Start a simple HTTP server to serve the [index.html](web/index.html)
    ```bash
    cd web
    python -m http.server 8000
    ```
3. Open your web browser and navigate to [http://localhost:8000](http://localhost:8000) to interact with the force graph.
