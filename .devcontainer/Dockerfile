# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y \
        build-essential linux-headers-generic bc \
        flex bison python3 python3-pip python3-venv git libelf-dev libssl-dev
WORKDIR /workspace
RUN git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
RUN cd linux && \
    make defconfig O=kernel-build && \
    make -j$(nproc) O=kernel-build
