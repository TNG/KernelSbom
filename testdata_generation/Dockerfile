# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

FROM ubuntu:25.04

RUN set -x \
    && apt-get -y update \
    && apt-get install -y --no-install-recommends \
        build-essential linux-headers-generic bc zstd ca-certificates \
        flex bison python3 git libelf-dev libssl-dev gawk sudo \
        # for rust builds 
        rustc rust-src rustfmt bindgen clang-20 lld-20 llvm-20-dev libclang-20-dev llvm-20-tools \
        # for ARM builds 
        gcc-aarch64-linux-gnu \
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

ARG GIT_BRANCH=v6.17
RUN git clone --depth 1 --branch "$GIT_BRANCH" https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git

ARG CONFIG=tinyconfig # tinyconfig, defconfig, allmodconfig
ARG ARCH=x86 # x86, arm64
ARG USE_RUST=false # false, true

SHELL ["/bin/bash", "-c"]
RUN set -eux; \
    cd linux; \
    MAKE_OPTIONS=(); \
    \
    # Architecture selection
    declare -A architecture_options=( \
        [x86]="ARCH=x86" \
        [arm64]="ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu-" \
    ); \
    MAKE_OPTIONS+=(${architecture_options[$ARCH]}); \
    \
    # Rust build
    if [ "$USE_RUST" = "true" ]; then \
        MAKE_OPTIONS+=("LLVM=1"); \
    fi; \
    \
    # Create configuration
    make O=kernel_build "${MAKE_OPTIONS[@]}" "$CONFIG"; \
    \
    # Enable Rust
    if [ "$USE_RUST" = "true" ]; then \
        ./scripts/config --file kernel_build/.config --enable RUST; \
        make O=kernel_build "${MAKE_OPTIONS[@]}" olddefconfig; \
    fi; \
    \
    # Build
    make -j"$(nproc)" O=kernel_build "${MAKE_OPTIONS[@]}"
