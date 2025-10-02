<!--
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SPDX-License-Identifier: GPL-2.0-only
-->

# Test Data Generation

This directory describes how the precompiled kernel builds in [KernelSbom-TestData](https://fileshare.tngtech.com/library/98e7e6f8-bffe-4a55-a8d2-817d4f3e51e8/KernelSbom-TestData/) were created.

Standard preconfigured kernel builds were obtained via:
- **linux-tinyconfig.tar.gz** `./extract_testdata.sh tinyconfig`
- **linux-defconfig.tar.gz** `./extract_testdata.sh defconfig`
- **linux-allmodconfig.tar.gz** `./extract_testdata.sh allmodconfig`

Additionally, distribution specific configs like **linux-localmodconfig.Ubuntu24.04.tar.gz** were created in different systems via: 
```bash
git clone --depth 1 --branch v6.17 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux
make localmodconfig O=kernel_build
make -j$(nproc) O=kernel_build
```

After building the kernel, the entire linux directory is archived and uploaded to the FileShare:
```bash
tar -czf linux-<config>.tar.gz linux
```
