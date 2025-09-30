<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

## CMD Graph Based Kernel Builds

This manually triggered workflow downloads a Linux kernel archive from:

https://fileshare.tngtech.com/d/e69946da808b41f88047/

The archive includes:
- The full Linux source tree
- A `kernel_build` directory with build output and `.config` used for the build

The workflow reconstructs a minimal source tree using only source files from the CMD graph and rebuilds the kernel using the original config.

Note: To add new test data to the library, build the Linux kernel using a specific configuration as follows:
```bash
cd linux
make <config_name> O=kernel_build
make -j$(nproc) O=kernel_build
cd ..
tar -czf linux-<config_name>.tar.gz linux
```
