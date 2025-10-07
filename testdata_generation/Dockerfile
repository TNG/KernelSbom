# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

FROM ubuntu:25.04

RUN set -x \
    && apt-get -y update \
    && apt-get install -y --no-install-recommends \
        build-essential linux-headers-generic bc zstd ca-certificates \
        flex bison python3 git libelf-dev libssl-dev gawk sudo \
        # rust setup 
        rustc rust-src rustfmt bindgen clang-20 lld-20 llvm-20-dev libclang-20-dev llvm-20-tools \
    && rm -rf /var/lib/apt/lists/*
RUN set -x \
    && ln -sf /usr/bin/clang-20 /usr/local/bin/clang \
    && ln -sf /usr/bin/ld.lld-20 /usr/local/bin/ld.lld \
    && ln -sf /usr/bin/llvm-ar-20 /usr/local/bin/llvm-ar \
    && ln -sf /usr/bin/llvm-nm-20 /usr/local/bin/llvm-nm \
    && ln -sf /usr/bin/llvm-objcopy-20 /usr/local/bin/llvm-objcopy \
    && ln -sf /usr/bin/llvm-strip-20 /usr/local/bin/llvm-strip \
    && ln -sf /usr/bin/llvm-objdump-20 /usr/local/bin/llvm-objdump \
    && echo "RUST_LIB_SRC=/usr/src/rustc-$(rustc --version | cut -d' ' -f2)/library" >> ~/.bashrc

WORKDIR /workspace

ARG GIT_TAG=v6.17
RUN git clone --depth 1 --branch "$GIT_TAG" https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

ARG CONFIG=defconfig
ARG USE_RUST=false
RUN set -x \
    && cd linux \
    && make $CONFIG O=kernel_build \
    && if [ "$USE_RUST" = "true" ]; then \
         ./scripts/config --file kernel_build/.config --enable RUST; \
         make olddefconfig O=kernel_build LLVM=1; \
         make -j$(nproc) O=kernel_build LLVM=1; \
       else \
        make -j$(nproc) O=kernel_build; \
       fi
