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
    --root-output vmlinux \
    --output sbom.spdx.json
  ```
Once complete, you should see the generated sbom.spdx.json file in your repository directory.

## Development & Debugging

For development and debugging, install the [Dev Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension for [VSCode](https://code.visualstudio.com/). Then, open the Command Palette (F1) and select `Reopen in Dev Container`. This opens your project inside a development container based on the same Dockerfile used above.
Inside the devcontainer, you can run the provided [Python Debugger: sbom](./.vscode/launch.json) launch configuration to step through the script interactively.