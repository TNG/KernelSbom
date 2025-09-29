#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
#
# SPDX-License-Identifier: GPL-2.0-only

from dataclasses import asdict, dataclass
import json
import logging
import os
import sys
from pathlib import Path
import gzip
import re

LIB_DIR = "../../sbom/lib"
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(SRC_DIR, LIB_DIR))

from sbom.cmd.cmd_graph import build_cmd_graph, CmdGraphNode, load_cmd_graph, save_cmd_graph  # noqa: E402

ForceGraphNodeId = str


@dataclass
class ForceGraphNode:
    id: ForceGraphNodeId
    depth: int
    root_node_index: int


@dataclass
class ForceGraphLink:
    source: ForceGraphNodeId
    target: ForceGraphNodeId


@dataclass
class ForceGraph:
    nodes: list[ForceGraphNode]
    links: list[ForceGraphLink]


def _cmd_graph_to_force_graph(
    cmd_graphs: list[CmdGraphNode], max_depth: int | None = None, filter_patterns: list[re.Pattern[str]] = []
) -> ForceGraph:
    nodes: list[ForceGraphNode] = []
    links: list[ForceGraphLink] = []

    # Keep track of visited nodes by their id to avoid duplicates
    visited: set[ForceGraphNodeId] = set()

    def traverse(node: CmdGraphNode, root_node_index: int, depth: int = 0):
        node_id = str(node.absolute_path)
        if node_id in visited:
            return

        nodes.append(ForceGraphNode(id=node_id, depth=depth, root_node_index=root_node_index))
        visited.add(node_id)

        if max_depth is not None and depth > max_depth:
            return

        for child in node.children:
            child_id = str(child.absolute_path)
            if any(pattern.search(child_id) for pattern in filter_patterns):
                continue
            links.append(ForceGraphLink(source=node_id, target=child_id))
            traverse(child, root_node_index, depth + 1)

    logging.info("Transforming CMD Graph to Force Graph:")
    for root_node_index, cmd_graph in enumerate(cmd_graphs):
        logging.info(f"{root_node_index}: {cmd_graph.absolute_path}")
        traverse(cmd_graph, root_node_index)

    return ForceGraph(nodes, links)


def get_missing_files(src_tree: Path) -> list[Path]:
    # return [
    #     Path("/workspace/linux/include/linux/export-internal.h"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/efistub.h"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/mem.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/randomalloc.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/pci.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/printk.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/tpm.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/smbios.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/relocate.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/random.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/alignedmem.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/file.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/skip_spaces.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/efi-stub-helper.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/gop.c"),
    #     Path("/workspace/linux/drivers/firmware/efi/libstub/secureboot.c"),
    #     Path("/workspace/linux/drivers/thermal/intel/x86_pkg_temp_thermal.c"),
    #     Path("/workspace/linux/net/ipv6/netfilter/nf_reject_ipv6.c"),
    #     Path("/workspace/linux/include/net/netfilter/nf_reject.h"),
    #     Path("/workspace/linux/include/net/netfilter/ipv6/nf_reject.h"),
    #     Path("/workspace/linux/net/netfilter/xt_addrtype.c"),
    #     Path("/workspace/linux/include/uapi/linux/netfilter/xt_addrtype.h"),
    #     Path("/workspace/linux/net/netfilter/nf_log_syslog.c"),
    #     Path("/workspace/linux/include/uapi/linux/netfilter/xt_LOG.h"),
    #     Path("/workspace/linux/net/netfilter/xt_mark.c"),
    #     Path("/workspace/linux/include/uapi/linux/netfilter/xt_mark.h"),
    #     Path("/workspace/linux/net/netfilter/xt_MASQUERADE.c"),
    #     Path("/workspace/linux/net/netfilter/xt_LOG.c"),
    #     Path("/workspace/linux/net/ipv4/netfilter/nf_reject_ipv4.c"),
    #     Path("/workspace/linux/include/net/netfilter/ipv4/nf_reject.h"),
    #     Path("/workspace/linux/arch/x86/boot/boot.h"),
    #     Path("/workspace/linux/arch/x86/boot/bitops.h"),
    #     Path("/workspace/linux/arch/x86/boot/ctype.h"),
    #     Path("/workspace/linux/arch/x86/boot/cpuflags.h"),
    #     Path("/workspace/linux/arch/x86/boot/io.h"),
    #     Path("/workspace/linux/arch/x86/boot/video-mode.c"),
    #     Path("/workspace/linux/include/linux/pe.h"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/video-mode.c"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/realmode.h"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/wakeup_asm.S"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/stack.S"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/header.S"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/trampoline_64.S"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/trampoline_common.S"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/wakemain.c"),
    #     Path("/workspace/linux/arch/x86/realmode/rm/reboot.S"),
    #     Path("/workspace/linux/arch/x86/tools/relocs_32.c"),
    #     Path("/workspace/linux/arch/x86/tools/relocs.h"),
    #     Path("/workspace/linux/arch/x86/tools/relocs.c"),
    #     Path("/workspace/linux/arch/x86/tools/relocs_64.c"),
    #     Path("/workspace/linux/arch/x86/tools/relocs_common.c"),
    # ]
    # Below is the full list of missing files. At the time of writing not all of these files can be processed due to missing command parsers in savedcmd_parser.py.
    # Comment out the list above to get a full graph of the missing files.
    return [
        # *_get_files_in_directory(src_tree / "scripts", source_patterns),
        # *_get_files_in_directory(src_tree / "tools", source_patterns),
        src_tree / "arch/x86/tools/relocs_32.c",
        src_tree / "arch/x86/tools/relocs.h",
        src_tree / "arch/x86/tools/relocs.c",
        src_tree / "arch/x86/tools/relocs_64.c",
        src_tree / "arch/x86/tools/relocs_common.c",
        # *_get_files_in_directory(src_tree / "include/asm-generic", source_patterns),
        src_tree / "include/asm-generic/fprobe.h",
        src_tree / "include/asm-generic/dma-mapping.h",
        src_tree / "include/asm-generic/module.lds.h",
        src_tree / "include/asm-generic/xor.h",
        # ...
        src_tree / "include/linux/kbuild.h",
        src_tree / "arch/x86/kernel/asm-offsets.c",
        src_tree / "include/crypto/aria.h",
        src_tree / "arch/x86/kernel/asm-offsets_64.c",
        src_tree / "arch/x86/entry/vdso/vdso.lds.S",
        src_tree / "arch/x86/entry/vdso/vdso-layout.lds.S",
        src_tree / "arch/x86/entry/vdso/vdso2c.c",
        src_tree / "arch/x86/entry/vdso/vdso2c.h",
        src_tree / "arch/x86/entry/vdso/vdso32/vdso32.lds.S",
        # *_get_files_in_directory(src_tree / "arch/x86/realmode/rm", source_patterns),
        src_tree / "arch/x86/realmode/rm/header.S",
        src_tree / "arch/x86/realmode/rm/realmode.h",
        src_tree / "arch/x86/realmode/rm/trampoline_64.S",
        src_tree / "arch/x86/realmode/rm/trampoline_common.S",
        src_tree / "arch/x86/realmode/rm/stack.S",
        src_tree / "arch/x86/realmode/rm/reboot.S",
        src_tree / "arch/x86/realmode/rm/wakeup_asm.S",
        src_tree / "arch/x86/realmode/rm/wakemain.c",
        src_tree / "arch/x86/realmode/rm/video-mode.c",
        # ...
        # *_get_files_in_directory(src_tree / "arch/x86/boot", source_patterns),
        src_tree / "arch/x86/boot/boot.h",
        src_tree / "arch/x86/boot/bitops.h",
        src_tree / "arch/x86/boot/ctype.h",
        src_tree / "arch/x86/boot/cpuflags.h",
        src_tree / "arch/x86/boot/io.h",
        src_tree / "arch/x86/boot/video-mode.c",
        # ....
        # *_get_files_in_directory(src_tree / "arch/x86/include", source_patterns),
        # *_get_files_in_directory(src_tree / "arch/x86/kernel", source_patterns),
        src_tree / "kernel/bounds.c",
        src_tree / "usr/gen_init_cpio.c",
        src_tree / "certs/extract-cert.c",
        src_tree / "fs/efivarfs/inode.c",
        src_tree / "fs/efivarfs/internal.h",
        src_tree / "fs/efivarfs/file.c",
        src_tree / "fs/efivarfs/super.c",
        src_tree / "fs/efivarfs/vars.c",
        src_tree / "security/selinux/genheaders.c",
        src_tree / "lib/crc/gen_crc32table.c",
        src_tree / "drivers/tty/vt/conmakehash.c",
        src_tree / "drivers/thermal/intel/x86_pkg_temp_thermal.c",
        # *_get_files_in_directory(src_tree / "drivers/firmware/efi/libstub", source_patterns),
        src_tree / "drivers/firmware/efi/libstub/alignedmem.c",
        src_tree / "drivers/firmware/efi/libstub/efistub.h",
        src_tree / "drivers/firmware/efi/libstub/efi-stub-helper.c",
        src_tree / "drivers/firmware/efi/libstub/file.c",
        src_tree / "drivers/firmware/efi/libstub/gop.c",
        src_tree / "drivers/firmware/efi/libstub/mem.c",
        src_tree / "drivers/firmware/efi/libstub/pci.c",
        src_tree / "drivers/firmware/efi/libstub/printk.c",
        src_tree / "drivers/firmware/efi/libstub/random.c",
        src_tree / "drivers/firmware/efi/libstub/randomalloc.c",
        src_tree / "drivers/firmware/efi/libstub/relocate.c",
        src_tree / "drivers/firmware/efi/libstub/secureboot.c",
        src_tree / "drivers/firmware/efi/libstub/skip_spaces.c",
        src_tree / "drivers/firmware/efi/libstub/smbios.c",
        src_tree / "drivers/firmware/efi/libstub/tpm.c",
        # ...
        src_tree / "net/netfilter/nf_log_syslog.c",
        src_tree / "net/ipv4/netfilter/nf_reject_ipv4.c",
        src_tree / "net/ipv6/netfilter/nf_reject_ipv6.c",
        src_tree / "net/netfilter/xt_mark.c",
        src_tree / "net/netfilter/xt_LOG.c",
        src_tree / "net/netfilter/xt_MASQUERADE.c",
        src_tree / "net/netfilter/xt_addrtype.c",
        src_tree / "include/uapi/linux/netfilter/xt_LOG.h",
        src_tree / "include/net/netfilter/ipv4/nf_reject.h",
        src_tree / "include/net/netfilter/nf_reject.h",
        src_tree / "include/net/netfilter/ipv6/nf_reject.h",
        src_tree / "include/uapi/linux/netfilter/xt_mark.h",
        src_tree / "include/uapi/linux/netfilter/xt_addrtype.h",
        src_tree / "include/linux/export-internal.h",
        src_tree / "include/linux/pe.h",
    ]


def cmd_graph_to_node_dict(
    node: CmdGraphNode, node_dict: dict[Path, CmdGraphNode] | None = None
) -> dict[Path, CmdGraphNode]:
    if node_dict is None:
        node_dict = {}
    node_dict[node.absolute_path] = node
    for child in node.children:
        cmd_graph_to_node_dict(child, node_dict)
    return node_dict


if __name__ == "__main__":
    script_path = Path(__file__).parent
    cmd_graph_path = script_path / "../cmd_graph.pickle"
    src_tree = (script_path / "../../linux").resolve()
    output_tree = (script_path / "../../linux/kernel_build").resolve()
    root_output_in_tree = Path("vmlinux")
    max_visualization_depth: int | None = None
    visualize_missing_files = True

    # Configure logging
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")

    # Load cached command graph if available, otherwise build it from .cmd files
    cmd_graph_node_cache: dict[Path, CmdGraphNode] = {}
    if cmd_graph_path.exists():
        logging.info("Loading cmd graph")
        cmd_graph = load_cmd_graph(cmd_graph_path)
        cmd_graph_node_cache = cmd_graph_to_node_dict(cmd_graph)
    else:
        cmd_graph = build_cmd_graph(root_output_in_tree, output_tree, src_tree, cmd_graph_node_cache)
        save_cmd_graph(cmd_graph, cmd_graph_path)

    # Extend cmd graph with missing files
    cmd_graphs: list[CmdGraphNode] = [CmdGraphNode(absolute_path=cmd_graph.absolute_path)]
    missing_files = get_missing_files(src_tree)
    logging.info("Add Graphs for missing files")
    for cmd_file_path in output_tree.rglob("*.o.cmd"):
        file_name = cmd_file_path.name.removeprefix(".").removesuffix(".cmd")
        file_path_abs = Path(os.path.realpath(cmd_file_path.parent)) / file_name
        cmd_graph_node_cache_keys = set(cmd_graph_node_cache.keys())
        if file_path_abs in cmd_graph_node_cache_keys:
            continue
        new_graph = build_cmd_graph(
            root_output_in_tree=file_path_abs.relative_to(output_tree),
            output_tree=output_tree,
            src_tree=src_tree,
            cache=cmd_graph_node_cache,
            log_graph_depth_limit=0,
        )
        found_files_in_new_graph = [
            p for p in missing_files if p in cmd_graph_node_cache.keys() and p not in cmd_graph_node_cache_keys
        ]
        logging.info(f"Found {len(found_files_in_new_graph)} additional files: {found_files_in_new_graph}")
        if len(found_files_in_new_graph) == 0:
            continue

        cmd_graphs.append(new_graph)
        missing_files = [f for f in missing_files if f not in found_files_in_new_graph]
        if len(missing_files) == 0:
            logging.info("Found all missing files")
            break

    # Create Force Graph representation
    force_graph = _cmd_graph_to_force_graph(
        cmd_graphs,
        max_depth=max_visualization_depth,
        filter_patterns=[re.compile(r"\.h$"), re.compile(r"^.*/include/config/")],
    )
    logging.info(f"Found {len(force_graph.nodes)} nodes.")

    # Save json data
    data_dict = asdict(force_graph)
    cmd_graph_json_gz_path = (
        script_path
        / "web"
        / ("vmlinux" if not visualize_missing_files else "vmlinux_with_missing_files")
        / "cmd_graph.json.gz"
    )
    with gzip.open(cmd_graph_json_gz_path, "wt", encoding="utf-8") as f:
        json.dump(data_dict, f)

    logging.info(f"Successfully Saved {cmd_graph_json_gz_path}.")
