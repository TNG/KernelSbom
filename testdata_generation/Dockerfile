# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

FROM ubuntu:22.04

RUN set -x \
    && apt-get -y update \
    && apt-get install -y --no-install-recommends \
        build-essential linux-headers-generic bc zstd ca-certificates \
        flex bison python3 git libelf-dev libssl-dev gawk sudo \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /workspace

RUN set -x \
    && useradd -m -s /bin/bash ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers \
    && chown ubuntu:ubuntu /workspace
USER ubuntu

ARG GIT_TAG=v6.17
RUN git clone --depth 1 --branch "$GIT_TAG" https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

ARG CONFIG=defconfig
RUN set -x \
    && cd linux \
    && make $CONFIG O=kernel_build \
    && make -j$(nproc) O=kernel_build
