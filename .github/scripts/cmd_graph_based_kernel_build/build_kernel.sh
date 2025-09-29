#!/bin/sh

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

# Usage: ./build_kernel.sh /path/to/linux/source
# $1 - Path to the Linux source tree directory (where to run the build)
#
# The script will create a 'kernel_build' directory inside this path,
# copy the current host kernel config, adjust it, and build the kernel there.

set -e

cd "$1"

rm -rf kernel_build
mkdir kernel_build

cp $(ls -1 /boot/config-* | tail -n 1) kernel_build/.config

# Disable configs to circumvent build issues
sed -i 's/^CONFIG_SYSTEM_TRUSTED_KEYS=.*/# CONFIG_SYSTEM_TRUSTED_KEYS is not set/' kernel_build/.config
sed -i 's/^CONFIG_SYSTEM_REVOCATION_KEYS=.*/# CONFIG_SYSTEM_REVOCATION_KEYS is not set/' kernel_build/.config

make olddefconfig O=kernel_build
make -j$(nproc) O=kernel_build
