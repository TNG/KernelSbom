# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import unittest

from lib.sbom.cmd.savedcmd_parser import parse_savedcmd


class TestSavedCmdParser(unittest.TestCase):
    def test_objcopy(self):
        cmd = "objcopy --remove-section='.rel*' --remove-section=!'.rel*.dyn' vmlinux.unstripped vmlinux"
        expected = ["vmlinux.unstripped"]
        self.assertEqual(parse_savedcmd(cmd), expected)

    def test_link_vmlinux(self):
        cmd = '../scripts/link-vmlinux.sh "ld" "-m elf_x86_64 -z noexecstack" "-z max-page-size=0x200000 --build-id=sha1 --orphan-handling=error --emit-relocs --discard-none" "vmlinux.unstripped";  true'
        expected = ["vmlinux.a"]
        self.assertEqual(parse_savedcmd(cmd), expected)

    # ar command tests

    def test_ar_reordering(self):
        """tests ar command in `.vmlinux.a.cmd` which first creates the archive and then moves some predefined entries to the top."""
        cmd = "rm -f vmlinux.a; ar cDPrST vmlinux.a built-in.a  lib/lib.a arch/x86/lib/lib.a; ar mPiT $$(ar t vmlinux.a | sed -n 1p) vmlinux.a $$(ar t vmlinux.a | grep -F -f ../scripts/head-object-list.txt)"
        expected = ["built-in.a", "lib/lib.a", "arch/x86/lib/lib.a"]
        self.assertEqual(parse_savedcmd(cmd), expected)

    def test_ar_default(self):
        """tests ar command in `.lib.a.cmd` which follows the default syntax."""
        cmd = "rm -f lib/lib.a; ar cDPrsT lib/lib.a lib/argv_split.o lib/bug.o lib/buildid.o lib/clz_tab.o lib/cmdline.o lib/cpumask.o lib/ctype.o lib/dec_and_lock.o lib/decompress.o lib/decompress_bunzip2.o lib/decompress_inflate.o lib/decompress_unlz4.o lib/decompress_unlzma.o lib/decompress_unlzo.o lib/decompress_unxz.o lib/decompress_unzstd.o lib/dump_stack.o lib/earlycpio.o lib/extable.o lib/flex_proportions.o lib/idr.o lib/iomem_copy.o lib/irq_regs.o lib/is_single_threaded.o lib/klist.o lib/kobject.o lib/kobject_uevent.o lib/logic_pio.o lib/maple_tree.o lib/memcat_p.o lib/nmi_backtrace.o lib/objpool.o lib/plist.o lib/radix-tree.o lib/ratelimit.o lib/rbtree.o lib/seq_buf.o lib/siphash.o lib/string.o lib/sys_info.o lib/timerqueue.o lib/union_find.o lib/vsprintf.o lib/win_minmax.o lib/xarray.o"
        expected = []
        self.assertEqual(parse_savedcmd(cmd), expected)

    def test_ar_printf(self):
        """tests ar command in `.built-in.a.cmd` which follows a `printf | xargs ar` syntax."""
        cmd = 'rm -f built-in.a;  printf "./%s " init/built-in.a usr/built-in.a arch/x86/built-in.a arch/x86/boot/startup/built-in.a kernel/built-in.a certs/built-in.a mm/built-in.a fs/built-in.a ipc/built-in.a security/built-in.a crypto/built-in.a block/built-in.a io_uring/built-in.a lib/built-in.a arch/x86/lib/built-in.a drivers/built-in.a sound/built-in.a net/built-in.a virt/built-in.a arch/x86/pci/built-in.a arch/x86/power/built-in.a arch/x86/video/built-in.a | xargs ar cDPrST built-in.a'
        expected = [
            "init/built-in.a",
            "usr/built-in.a",
            "arch/x86/built-in.a",
            "arch/x86/boot/startup/built-in.a",
            "kernel/built-in.a",
            "certs/built-in.a",
            "mm/built-in.a",
            "fs/built-in.a",
            "ipc/built-in.a",
            "security/built-in.a",
            "crypto/built-in.a",
            "block/built-in.a",
            "io_uring/built-in.a",
            "lib/built-in.a",
            "arch/x86/lib/built-in.a",
            "drivers/built-in.a",
            "sound/built-in.a",
            "net/built-in.a",
            "virt/built-in.a",
            "arch/x86/pci/built-in.a",
            "arch/x86/power/built-in.a",
            "arch/x86/video/built-in.a",
        ]
        self.assertEqual(parse_savedcmd(cmd), expected)

    def test_ar_printf_nested(self):
        """tests ar command in `arch/x86/pci/.built-in.a.cmd` which follows a `printf | xargs ar` syntax."""
        cmd = 'rm -f arch/x86/pci/built-in.a;  printf "arch/x86/pci/%s " i386.o init.o mmconfig_64.o direct.o mmconfig-shared.o fixup.o acpi.o legacy.o irq.o common.o early.o bus_numa.o amd_bus.o | xargs ar cDPrST arch/x86/pci/built-in.a'
        expected = [
            "i386.o",
            "init.o",
            "mmconfig_64.o",
            "direct.o",
            "mmconfig-shared.o",
            "fixup.o",
            "acpi.o",
            "legacy.o",
            "irq.o",
            "common.o",
            "early.o",
            "bus_numa.o",
            "amd_bus.o",
        ]
        self.assertEqual(parse_savedcmd(cmd), expected)

    # gcc command tests

    def test_gcc(self):
        """tests gcc command in `arch/x86/pci/.i386.o.cmd`"""
        cmd = (
            "gcc -Wp,-MMD,arch/x86/pci/.i386.o.d -nostdinc -I../arch/x86/include -I./arch/x86/include/generated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I../include/uapi -I./include/generated/uapi -include ../include/linux/compiler-version.h -include ../include/linux/kconfig.h -include ../include/linux/compiler_types.h -D__KERNEL__ -fmacro-prefix-map=../= -Werror -std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=branch -fno-jump-tables -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -march=x86-64 -mtune=generic -mno-red-zone -mcmodel=kernel -mstack-protector-guard-reg=gs -mstack-protector-guard-symbol=__ref_stack_chk_guard -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -mindirect-branch-cs-prefix -mfunction-return=thunk-extern -fno-jump-tables -fpatchable-function-entry=16,16 -fno-delete-null-pointer-checks -O2 -fno-allow-store-data-races -fstack-protector-strong -fomit-frame-pointer -fno-stack-clash-protection -falign-functions=16 -fno-strict-overflow -fno-stack-check -fconserve-stack -fno-builtin-wcslen -Wall -Wextra -Wundef -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Werror=strict-prototypes -Wno-format-security -Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member -Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=2048 -Wno-main -Wvla-larger-than=1 -Wno-pointer-sign -Wcast-function-type -Wno-array-bounds -Wno-stringop-overflow -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wenum-conversion -Wunused -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-packed-not-aligned -Wno-format-overflow -Wno-format-truncation -Wno-stringop-truncation -Wno-override-init -Wno-missing-field-initializers -Wno-type-limits -Wno-shift-negative-value -Wno-maybe-uninitialized -Wno-sign-compare -Wno-unused-parameter -I../arch/x86/pci -Iarch/x86/pci    -DKBUILD_MODFILE="
            "arch/x86/pci/i386"
            " -DKBUILD_BASENAME="
            "i386"
            " -DKBUILD_MODNAME="
            "i386"
            " -D__KBUILD_MODNAME=kmod_i386 -c -o arch/x86/pci/i386.o ../arch/x86/pci/i386.c  "
        )
        expected = ["i386.c"]
        self.assertEqual(parse_savedcmd(cmd), expected)


if __name__ == "__main__":
    unittest.main()
