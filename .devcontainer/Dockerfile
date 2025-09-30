# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

FROM ubuntu:22.04
RUN set -x \
    && apt-get -y update \
    && apt-get install -y --no-install-recommends \
        build-essential linux-headers-generic bc \
        flex bison python3 python3-pip python3-venv git libelf-dev libssl-dev gawk sudo \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace

RUN set -x \
    && useradd -m -s /bin/bash ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && chown ubuntu:ubuntu /workspace
USER ubuntu

RUN git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
ARG CONFIG=defconfig
RUN set -x \
    && cd linux \
    && make $CONFIG O=kernel_build \
    && make -j$(nproc) O=kernel_build
