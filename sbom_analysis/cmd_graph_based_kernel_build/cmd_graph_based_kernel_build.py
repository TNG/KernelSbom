#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

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


def _run_command(cmd: list[str], cwd: Path) -> tuple[int, list[str]]:
    result = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    output = result.stdout.splitlines()
    return result.returncode, output


def _find_make_error(strace_outputs: list[str]) -> str:
    make_error_patterns = [
        r"No rule to make target '([^'\s]+)'",
        r"([^'\s]+): No such file or directory",
        r"cannot open ([^'\s]+): No such file",
    ]
    error = next(
        (line for line in reversed(strace_outputs) if any(re.search(pattern, line) for pattern in make_error_patterns)),
        None,
    )
    return error


def _get_potential_missing_files(strace_outputs: list[str], src_tree: Path, output_tree: Path) -> list[Path]:
    """
    parses the strace output and returns potentially missing files that could fix the make error.
    """
    make_error_patterns = [
        r"No rule to make target '([^'\s]+)'",
        r"([^'\s]+): No such file or directory",
        r"cannot open ([^'\s]+): No such file",
    ]

    error_index = next(
        (
            i
            for i, line in reversed(list(enumerate(strace_outputs)))
            if any(re.search(pattern, line) for pattern in make_error_patterns)
        ),
        None,
    )
    if error_index is None:
        raise RuntimeError("Build failed, but no missing file was found in strace output.")

    strace_open_pattern = r'open(?:at)?\(.*?,\s+"([^"]+)"'
    potential_missing_files: list[Path] = []
    for p in re.findall(strace_open_pattern, "".join(strace_outputs[:error_index])):
        path = Path(p) if Path(p).is_absolute() else (output_tree / p).resolve()
        if path.is_file() and path.is_relative_to(src_tree) and not path.is_relative_to(output_tree) and path.exists():
            potential_missing_files.append(path.relative_to(src_tree))

    return potential_missing_files


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


def find_candidates_for_fixing_make_error(make_error_path: Path, src_tree: Path) -> list[Path]:
    """
    This function searches for candidate files that potentially fix the make error

    make_error_path is the path that is mentioned in the make error message.

    Returns
    candidate_files (list[Path])   list of potential files that are missing and caused make to fail. paths are provided relative to src_tree
    """
    candidate_files: list[Path] = []
    _make_error_path = Path(*make_error_path.parts)
    while len(candidate_files) == 0:
        logging.info(f"Searching src_tree for {_make_error_path}")
        candidate_files = [
            Path(os.path.relpath(found_source, src_tree))
            for found_source in src_tree.rglob(str(_make_error_path))
            if not found_source.is_relative_to(cmd_output_tree)
        ]
        _make_error_path = Path(*_make_error_path.parts[1:])
        if len(_make_error_path.parts) == 0:
            break

    if len(candidate_files) > 0:
        return candidate_files

    suffix_replacements = [
        (".s", ".c"),
        (".o", ".c"),
        (".o", ".S"),
        (".lds", ".lds.S"),
    ]
    for suffix, replacement_suffix in suffix_replacements:
        if not make_error_path.name.endswith(suffix):
            continue
        replaced_path = make_error_path.parent / make_error_path.name.replace(suffix, replacement_suffix)
        candidate_files += find_candidates_for_fixing_make_error(replaced_path, src_tree)
    return candidate_files


def _attempt_kernel_build(
    missing_sources_in_cmd_graph: list[Path],
    cmd_src_tree: Path,
    cmd_output_tree: Path,
    missing_sources_in_cmd_graph_path: Path,
) -> None:
    previous_make_error: str | None = None
    potential_missing_file: Path | None = None
    while True:
        logging.info("Attempting to build kernel")
        returncode, strace_outputs = _run_command(
            f"strace -f -e trace=openat -s 200 make O={cmd_output_tree.relative_to(cmd_src_tree)}".split(" "),
            cmd_src_tree,
        )
        if returncode == 0:
            logging.info("Successfully built kernel")
            return

        make_error = _find_make_error(strace_outputs)
        if make_error is None:
            raise RuntimeError("Build failed, but no missing file was found in strace output.")
        logging.info(f"Build failed with: {make_error}")

        is_new_error = make_error != previous_make_error
        if is_new_error:
            if potential_missing_file:
                # potential missing file from last iteration indeed fixed the previous error
                missing_sources_in_cmd_graph.append(potential_missing_file)
                with open(missing_sources_in_cmd_graph_path, "wt") as f:
                    json.dump([str(source_file) for source_file in missing_sources_in_cmd_graph], f, indent=2)
            # Create new list of potential missing files
            potential_missing_files = reversed(_get_potential_missing_files(strace_outputs, src_tree, output_tree))
            previous_make_error = make_error
        elif potential_missing_file:
            # delete previously copied file which did not fix the error
            (cmd_src_tree / potential_missing_file).unlink()

        # get new candidate if there are remaining
        potential_missing_file = next(potential_missing_files)
        if potential_missing_file is None:
            raise RuntimeError("Found no file in the source tree that could fix the build error.")

        # copy new candidate
        logging.info(f"Detected {potential_missing_file} in make error output")
        shutil.copy2(src_tree / potential_missing_file, cmd_src_tree / potential_missing_file)


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
            # "tools/include/linux/types.h",
            # "include/asm-generic/fprobe.h",
            # "include/asm-generic/dma-mapping.h",
            # "include/asm-generic/module.lds.h",
            # "include/asm-generic/xor.h",
            # "scripts/mod/empty.c",
            # "tools/include/linux/string.h",
            # "tools/include/linux/kernel.h",
            # "tools/lib/string.c",
            # "tools/lib/rbtree.c",
            # "include/linux/nsfs.h",
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
    _attempt_kernel_build(
        missing_sources_in_cmd_graph,
        cmd_src_tree,
        cmd_output_tree,
        missing_sources_in_cmd_graph_path=script_path / "missing_sources_in_cmd_graph.json",
    )
