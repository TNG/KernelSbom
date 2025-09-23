<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

# LinuxKernelSbomGenerator

A script to generate an SPDX-format Software Bill of Materials (SBOM) for the `vmlinux` kernel build.
The eventual goal is to integrate the `sbom/` directory into the `linux/scripts/` directory in the official [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/) kernel source tree.

## Getting Started

To test the script install [Docker](https://docs.docker.com/engine/install/ubuntu/#installation-methods) and run:
```bash
docker compose up
```
This will:
- Build a Docker image based on the included [Dockerfile](./Dockerfile).
- Clone the Linux kernel repository during the image build.
- Compile the kernel out-of-tree into `linux/kernel-build`.
- Start a container with this repository mounted as volume.
- Run the [sbom.py](sbom/sbom.py) script inside the container:
  ```bash
  python3 sbom/sbom.py \
    --src-tree ../linux \
    --output-tree ../linux/kernel-build \
    --root-output-in-tree vmlinux \
    --output sbom.spdx.json
  ```
Once complete, you should see the generated `sbom.spdx.json` file in your repository directory.

## Directory Structure

- `sbom/`
  - [sbom.py](sbom/sbom.py) - The main script responsible for generating the SBOM.
  - `sbom/lib/sbom` - Library modules used by the main script.
  - `sbom/lib/sbom_tests` - Unit tests for the library modules.
- `sbom_analysis` - Additional scripts for analyzing the outputs produced by the main script.
  - [sbom_analysis/cmd_graph_based_kernel_build](sbom_analysis/cmd_graph_based_kernel_build/README.md) - Validation of cmd graph completeness by rebuilding the linux kernel only with files referenced in the cmd graph.
  - [sbom_analysis/cmd_graph_visualization](sbom_analysis/cmd_graph_visualization/README.md) - Interactive visualization of the cmd graph

The main contribution is the content of the `sbom` directory which eventually should be moved into the `linux/scripts/` directory in the official [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/) kernel source tree.

## Development & Debugging

For development and debugging, install the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension for [VSCode](https://code.visualstudio.com/). Then, open the Command Palette (F1) and select `Reopen in Dev Container`. This opens your project inside a development container based on the same Dockerfile used above.
Inside the devcontainer, you can run the provided [Python Debugger: sbom](./.vscode/launch.json) launch configuration to step through the script interactively.

## Reuse

when commiting `reuse lint` is executed as a pre-commit hook to check if all files have compliant License headers. If any file is missing a license header add it via 
```
reuse annotate --license="GPL-2.0-only" --copyright="TNG Technology Consulting GmbH" <filename>
```
