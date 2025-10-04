#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

import json
import logging
import os
import re
import shutil
import sys
from pathlib import Path
from build_kernel import build_kernel

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd.cmd_graph import build_or_load_cmd_graph, iter_files_in_cmd_graph  # noqa: E402


def _remove_files(base_path: Path, patterns_to_remove: list[re.Pattern[str]], ignore: set[Path]) -> list[Path]:
    removed_files: list[Path] = []
    for file_path in base_path.rglob("*"):
        if (
            not file_path.is_file()
            or file_path.relative_to(base_path) in ignore
            or not any(p.match(str(file_path)) for p in patterns_to_remove)
        ):
            continue

        file_path.unlink()
        removed_files.append(file_path)
    return removed_files


def _create_cmd_graph_based_kernel_directory(
    src_tree: Path,
    output_tree: Path,
    cmd_src_tree: Path,
    cmd_output_tree: Path,
    root_output_in_tree: Path,
    cmd_graph_path: Path,
    missing_sources_in_cmd_graph: list[Path],
) -> None:
    logging.info(f"Copy {src_tree} into {cmd_src_tree}")
    shutil.copytree(src_tree, cmd_src_tree, ignore=shutil.ignore_patterns(output_tree.relative_to(src_tree)))
    cmd_output_tree.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(output_tree / ".config", cmd_output_tree / ".config")

    # Load cached command graph or build it from .cmd files
    cmd_graph = build_or_load_cmd_graph(root_output_in_tree, output_tree, src_tree, cmd_graph_path)

    # remove source files not in cmd_graph
    source_patterns = [
        re.compile(r".*\.c$"),
        re.compile(r".*\.h$"),
        re.compile(r".*\.S$"),
    ]
    logging.info("Extract source files from cmd graph")
    cmd_graph_sources = [
        file_path.relative_to(src_tree)
        for file_path in iter_files_in_cmd_graph(cmd_graph)
        if not any(pattern.search(str(cmd_graph.absolute_path)) for pattern in source_patterns)
    ]

    logging.info("Remove source files not in cmd graph")
    _remove_files(
        cmd_src_tree,
        patterns_to_remove=source_patterns,
        ignore=set(cmd_graph_sources + missing_sources_in_cmd_graph),
    )

    # additional_sources: list[Path] = [
    #     s.relative_to(src_tree)
    #     for s in [
    #         # *_get_files_in_directory(src_tree / "scripts", source_patterns),
    #         # *_get_files_in_directory(src_tree / "tools", source_patterns),
    #         src_tree / "arch/x86/tools/relocs_32.c",
    #         src_tree / "arch/x86/tools/relocs.h",
    #         src_tree / "arch/x86/tools/relocs.c",
    #         src_tree / "arch/x86/tools/relocs_64.c",
    #         src_tree / "arch/x86/tools/relocs_common.c",
    #         # *_get_files_in_directory(src_tree / "include/asm-generic", source_patterns),
    #         src_tree / "include/asm-generic/fprobe.h",
    #         src_tree / "include/asm-generic/dma-mapping.h",
    #         src_tree / "include/asm-generic/module.lds.h",
    #         src_tree / "include/asm-generic/xor.h",
    #         # ...
    #         src_tree / "include/linux/kbuild.h",
    #         src_tree / "arch/x86/kernel/asm-offsets.c",
    #         src_tree / "include/crypto/aria.h",
    #         src_tree / "arch/x86/kernel/asm-offsets_64.c",
    #         src_tree / "arch/x86/entry/vdso/vdso.lds.S",
    #         src_tree / "arch/x86/entry/vdso/vdso-layout.lds.S",
    #         src_tree / "arch/x86/entry/vdso/vdso2c.c",
    #         src_tree / "arch/x86/entry/vdso/vdso2c.h",
    #         src_tree / "arch/x86/entry/vdso/vdso32/vdso32.lds.S",
    #         # *_get_files_in_directory(src_tree / "arch/x86/realmode/rm", source_patterns),
    #         src_tree / "arch/x86/realmode/rm/header.S",
    #         src_tree / "arch/x86/realmode/rm/realmode.h",
    #         src_tree / "arch/x86/realmode/rm/trampoline_64.S",
    #         src_tree / "arch/x86/realmode/rm/trampoline_common.S",
    #         src_tree / "arch/x86/realmode/rm/stack.S",
    #         src_tree / "arch/x86/realmode/rm/reboot.S",
    #         src_tree / "arch/x86/realmode/rm/wakeup_asm.S",
    #         src_tree / "arch/x86/realmode/rm/wakemain.c",
    #         src_tree / "arch/x86/realmode/rm/video-mode.c",
    #         # ...
    #         # *_get_files_in_directory(src_tree / "arch/x86/boot", source_patterns),
    #         src_tree / "arch/x86/boot/boot.h",
    #         src_tree / "arch/x86/boot/bitops.h",
    #         src_tree / "arch/x86/boot/ctype.h",
    #         src_tree / "arch/x86/boot/cpuflags.h",
    #         src_tree / "arch/x86/boot/io.h",
    #         src_tree / "arch/x86/boot/video-mode.c",
    #         # ....
    #         # *_get_files_in_directory(src_tree / "arch/x86/include", source_patterns),
    #         # *_get_files_in_directory(src_tree / "arch/x86/kernel", source_patterns),
    #         src_tree / "kernel/bounds.c",
    #         src_tree / "usr/gen_init_cpio.c",
    #         src_tree / "certs/extract-cert.c",
    #         src_tree / "fs/efivarfs/inode.c",
    #         src_tree / "fs/efivarfs/internal.h",
    #         src_tree / "fs/efivarfs/file.c",
    #         src_tree / "fs/efivarfs/super.c",
    #         src_tree / "fs/efivarfs/vars.c",
    #         src_tree / "security/selinux/genheaders.c",
    #         src_tree / "lib/crc/gen_crc32table.c",
    #         src_tree / "drivers/tty/vt/conmakehash.c",
    #         src_tree / "drivers/thermal/intel/x86_pkg_temp_thermal.c",
    #         # *_get_files_in_directory(src_tree / "drivers/firmware/efi/libstub", source_patterns),
    #         src_tree / "drivers/firmware/efi/libstub/alignedmem.c",
    #         src_tree / "drivers/firmware/efi/libstub/efistub.h",
    #         src_tree / "drivers/firmware/efi/libstub/efi-stub-helper.c",
    #         src_tree / "drivers/firmware/efi/libstub/file.c",
    #         src_tree / "drivers/firmware/efi/libstub/gop.c",
    #         src_tree / "drivers/firmware/efi/libstub/mem.c",
    #         src_tree / "drivers/firmware/efi/libstub/pci.c",
    #         src_tree / "drivers/firmware/efi/libstub/printk.c",
    #         src_tree / "drivers/firmware/efi/libstub/random.c",
    #         src_tree / "drivers/firmware/efi/libstub/randomalloc.c",
    #         src_tree / "drivers/firmware/efi/libstub/relocate.c",
    #         src_tree / "drivers/firmware/efi/libstub/secureboot.c",
    #         src_tree / "drivers/firmware/efi/libstub/skip_spaces.c",
    #         src_tree / "drivers/firmware/efi/libstub/smbios.c",
    #         src_tree / "drivers/firmware/efi/libstub/tpm.c",
    #         # ...
    #         src_tree / "net/netfilter/nf_log_syslog.c",
    #         src_tree / "net/ipv4/netfilter/nf_reject_ipv4.c",
    #         src_tree / "net/ipv6/netfilter/nf_reject_ipv6.c",
    #         src_tree / "net/netfilter/xt_mark.c",
    #         src_tree / "net/netfilter/xt_LOG.c",
    #         src_tree / "net/netfilter/xt_MASQUERADE.c",
    #         src_tree / "net/netfilter/xt_addrtype.c",
    #         src_tree / "include/uapi/linux/netfilter/xt_LOG.h",
    #         src_tree / "include/net/netfilter/ipv4/nf_reject.h",
    #         src_tree / "include/net/netfilter/nf_reject.h",
    #         src_tree / "include/net/netfilter/ipv6/nf_reject.h",
    #         src_tree / "include/uapi/linux/netfilter/xt_mark.h",
    #         src_tree / "include/uapi/linux/netfilter/xt_addrtype.h",
    #         src_tree / "include/linux/export-internal.h",
    #         src_tree / "include/linux/pe.h",
    #     ]
    # ]


if __name__ == "__main__":
    script_path = Path(__file__).parent
    # Paths to the original source and build directories
    cmd_graph_path = (script_path / "../cmd_graph.pickle").resolve()
    src_tree = (script_path / "../../linux").resolve()
    output_tree = (script_path / "../../linux/kernel_build").resolve()
    root_output_in_tree = Path("vmlinux")
    cmd_src_tree = (script_path / "../../linux_cmd").resolve()
    cmd_output_tree = (script_path / "../../linux_cmd/kernel_build").resolve()

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    missing_sources_in_cmd_graph: list[Path] = [
        # The missing files that had to be added manually because parsing the error messages was too hard:
        Path(s)
        for s in [
            # "include/asm-generic/fprobe.h",
            # "include/asm-generic/dma-mapping.h",
            # "include/asm-generic/module.lds.h",
            # "include/asm-generic/xor.h",
            # "scripts/mod/empty.c",
            # "tools/lib/string.c",
            # "tools/lib/rbtree.c",
            # "include/linux/nsfs.h",
            "tools/include/linux/types.h",
            "tools/include/linux/kernel.h",
            "arch/x86/include/uapi/asm/stat.h",
            # "tools/include/linux/string.h",
        ]
    ]
    if (script_path / "missing_sources_in_cmd_graph.json").exists():
        with open(script_path / "missing_sources_in_cmd_graph.json", "r") as f:
            missing_sources_in_cmd_graph += [Path(p) for p in json.load(f)]

    if not cmd_src_tree.exists():
        _create_cmd_graph_based_kernel_directory(
            src_tree,
            output_tree,
            cmd_src_tree,
            cmd_output_tree,
            root_output_in_tree,
            cmd_graph_path,
            missing_sources_in_cmd_graph,
        )
    build_kernel(
        missing_sources_in_cmd_graph,
        cmd_src_tree,
        cmd_output_tree,
        src_tree,
        output_tree,
        missing_sources_in_cmd_graph_path=script_path / "missing_sources_in_cmd_graph.json",
    )
