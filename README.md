<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>

SPDX-License-Identifier: GPL-2.0-only
-->

# LinuxKernelSbomGenerator

A script to generate an SPDX-format Software Bill of Materials (SBOM) for the `vmlinux` kernel build.

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
- Automatically run the [sbom.py](./sbom.py) script inside the container:
  ```bash
  python3 sbom.py \
    --src-tree ../linux \
    --output-tree ../linux/kernel-build \
    --root-output-in-tree vmlinux \
    --output sbom.spdx.json
  ```
Once complete, you should see the generated `sbom.spdx.json` file in your repository directory.

## Development & Debugging

For development and debugging, install the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension for [VSCode](https://code.visualstudio.com/). Then, open the Command Palette (F1) and select `Reopen in Dev Container`. This opens your project inside a development container based on the same Dockerfile used above.
Inside the devcontainer, you can run the provided [Python Debugger: sbom](./.vscode/launch.json) launch configuration to step through the script interactively.

## Reuse

when commiting `rerun lint` is executed as a pre-commit hook to check if all files have compliant License headers. If any file is missing a license header add it via 
```
reuse annotate --license="GPL-2.0-only" --copyright="TNG Technology Consulting GmbH <info@tngtech.com>" <filename>
```
