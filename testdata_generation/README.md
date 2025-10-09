<!--
SPDX-License-Identifier: GPL-2.0-only
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
-->

# Test Data Generation

This directory describes how the precompiled kernel builds in [KernelSbom-TestData](https://fileshare.tngtech.com/library/98e7e6f8-bffe-4a55-a8d2-817d4f3e51e8/KernelSbom-TestData/) were created.

Standard preconfigured kernel builds were obtained via:
- **linux.v6.17.tinyconfig.tar.gz** `./extract_testdata.sh tinyconfig`
- **linux.v6.17.defconfig.tar.gz** `./extract_testdata.sh defconfig`
- **linux.v6.17.allmodconfig.tar.gz** `./extract_testdata.sh allmodconfig`

Additionally, distribution specific configs like **linux.v6.17.localmodconfig.Ubuntu24.04.tar.gz** were created via: 
```bash
git clone --depth 1 --branch v6.17 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
cd linux
make localmodconfig O=kernel_build
make -j$(nproc) O=kernel_build

# Depending on the config some options might need to be disabled to make the build work.
scripts/config --file kernel_build/.config --undefine CONFIG_SYSTEM_REVOCATION_KEYS
scripts/config --file kernel_build/.config --undefine CONFIG_SYSTEM_REVOCATION_LIST
```

After building the kernel, the entire linux directory is archived and uploaded to the FileShare:
The following naming schema is used:
```bash
tar -czf linux.<version>.<config>.<rust>.tar.gz linux
```
