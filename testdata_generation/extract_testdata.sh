#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: Maximilian Huber <maximilian.huber@tngtech.com>

set -euo pipefail

script="$(readlink -f "$0")"
dockerfile="$(dirname "$script")/Dockerfile"

if ! command -v podman &> /dev/null; then
    echo "podman is not installed"
    exit 1
fi

get_config() {
    local config=defconfig
    local supported_configs=(defconfig allyesconfig allmodconfig allnoconfig randconfig localmodconfig tinyconfig)
    if [[ "$#" -gt 0 ]]; then
        if [[ " ${supported_configs[@]} " =~ " ${1} " ]]; then
            config="$1"
        else
            echo "unexpected config: $1"
            echo "supported configs: ${supported_configs[@]}"
            exit 1
        fi
    fi
    echo "$config"
}

build_image() {
    local config="$1"
    local tag="$2"
    local uuid=$(set -x; cat $dockerfile | podman build --build-arg CONFIG="$config" -f - --tag "$tag" | tail -n 1)
    if [[ -z "$uuid" ]]; then
        echo "failed to build image"
        exit 1
    fi
    >&2 echo "build_image: $uuid"
    echo "$uuid"
}

mount_image() {
    local uuid="$1"
    local mnt=$(set -x; podman image mount $uuid) 
    if [[ -z "$mnt" ]]; then
        echo "failed to mount image"
        exit 1
    fi
    >&2 echo "mount_image: $mnt"
    echo "$mnt"
}

copy_testdata() {
    set -x
    local mnt="$1"
    local output="$2"
    (set -x; cp -r $mnt/workspace/linux $output)
}

main() {
    local config="$(get_config "$@")"
    local output="$(dirname $(dirname "$script"))/linux.$config"

    if [[ -d "$output" ]]; then
        echo "output=${output} already exists"
        exit 1
    fi

    local tag="tng/kernel-sbom-devcontainer:$config"

    local uuid=$(build_image "$config" "$tag")
    trap "podman rm -f $uuid" EXIT
    local mnt=$(mount_image "$uuid") 
    trap "podman image umount $uuid; sleep 1; podman rm -f $uuid" EXIT
    copy_testdata "$mnt" "$output"
}

if [[ "$#" -eq 0 || "$1" != --unshared ]]; then
    podman unshare $script --unshared "$@"
elif [[ "$1" == --unshared ]]; then
    shift
    main "$@"
    times
fi
