<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

# Test Data Generation

This directory describes how the precompiled kernel builds in [KernelSbom-TestData](https://fileshare.tngtech.com/library/98e7e6f8-bffe-4a55-a8d2-817d4f3e51e8/KernelSbom-TestData/) were created.

Standard preconfigured kernel builds were obtained via:
- linux-tinyconfig.tar.gz `./extract_testdata.sh tinyconfig`
- linux-defconfig.tar.gz `./extract_testdata.sh defconfig`
- linux-allmodconfig.tar.gz `./extract_testdata.sh allmodconfig`

Additionally, the `configs` directory includes distribution-specific configs. The respective precompiled kernel builds were created using:

```bash
git clone --depth 1 --branch v6.17 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
mkdir linux/kernel_build
cp configs/<config> linux/kernel_build/.config
cd linux
make olddefconfig O=kernel_build
make -j$(nproc) O=kernel_build
```

After building the kernel, the entire linux directory is archived and uploaded to the FileShare:
```bash
tar -czf linux-<config>.tar.gz linux
```
