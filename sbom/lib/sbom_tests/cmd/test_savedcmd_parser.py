# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

from pathlib import Path
import unittest

from sbom.cmd.savedcmd_parser import parse_commands


class TestSavedCmdParser(unittest.TestCase):
    # objcopy command tests

    def test_objcopy(self):
        cmd = "objcopy --remove-section='.rel*' --remove-section=!'.rel*.dyn' vmlinux.unstripped vmlinux"
        expected = [Path("vmlinux.unstripped")]
        self.assertEqual(parse_commands(cmd), expected)

    def test_objcopy_llvm(self):
        cmd = "llvm-objcopy --remove-section='.rel*' --remove-section=!'.rel*.dyn' vmlinux.unstripped vmlinux"
        expected = [Path("vmlinux.unstripped")]
        self.assertEqual(parse_commands(cmd), expected)

    # link-vmlinux.sh command tests

    def test_link_vmlinux(self):
        cmd = '../scripts/link-vmlinux.sh "ld" "-m elf_x86_64 -z noexecstack" "-z max-page-size=0x200000 --build-id=sha1 --orphan-handling=error --emit-relocs --discard-none" "vmlinux.unstripped";  true'
        expected = [Path("vmlinux.a")]
        self.assertEqual(parse_commands(cmd), expected)

    # ar command tests

    def test_ar_reordering(self):
        """tests ar command in `.vmlinux.a.cmd` which first creates the archive and then moves some predefined entries to the top."""
        cmd = "rm -f vmlinux.a; ar cDPrST vmlinux.a built-in.a  lib/lib.a arch/x86/lib/lib.a; ar mPiT $$(ar t vmlinux.a | sed -n 1p) vmlinux.a $$(ar t vmlinux.a | grep -F -f ../scripts/head-object-list.txt)"
        expected = ["built-in.a", "lib/lib.a", "arch/x86/lib/lib.a"]
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected])

    def test_ar_default(self):
        """tests ar command in `.lib.a.cmd` which follows the default syntax."""
        cmd = "rm -f lib/lib.a; ar cDPrsT lib/lib.a lib/argv_split.o lib/bug.o lib/buildid.o lib/clz_tab.o lib/cmdline.o lib/cpumask.o lib/ctype.o lib/dec_and_lock.o lib/decompress.o lib/decompress_bunzip2.o lib/decompress_inflate.o lib/decompress_unlz4.o lib/decompress_unlzma.o lib/decompress_unlzo.o lib/decompress_unxz.o lib/decompress_unzstd.o lib/dump_stack.o lib/earlycpio.o lib/extable.o lib/flex_proportions.o lib/idr.o lib/iomem_copy.o lib/irq_regs.o lib/is_single_threaded.o lib/klist.o lib/kobject.o lib/kobject_uevent.o lib/logic_pio.o lib/maple_tree.o lib/memcat_p.o lib/nmi_backtrace.o lib/objpool.o lib/plist.o lib/radix-tree.o lib/ratelimit.o lib/rbtree.o lib/seq_buf.o lib/siphash.o lib/string.o lib/sys_info.o lib/timerqueue.o lib/union_find.o lib/vsprintf.o lib/win_minmax.o lib/xarray.o"
        expected = "lib/argv_split.o lib/bug.o lib/buildid.o lib/clz_tab.o lib/cmdline.o lib/cpumask.o lib/ctype.o lib/dec_and_lock.o lib/decompress.o lib/decompress_bunzip2.o lib/decompress_inflate.o lib/decompress_unlz4.o lib/decompress_unlzma.o lib/decompress_unlzo.o lib/decompress_unxz.o lib/decompress_unzstd.o lib/dump_stack.o lib/earlycpio.o lib/extable.o lib/flex_proportions.o lib/idr.o lib/iomem_copy.o lib/irq_regs.o lib/is_single_threaded.o lib/klist.o lib/kobject.o lib/kobject_uevent.o lib/logic_pio.o lib/maple_tree.o lib/memcat_p.o lib/nmi_backtrace.o lib/objpool.o lib/plist.o lib/radix-tree.o lib/ratelimit.o lib/rbtree.o lib/seq_buf.o lib/siphash.o lib/string.o lib/sys_info.o lib/timerqueue.o lib/union_find.o lib/vsprintf.o lib/win_minmax.o lib/xarray.o"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    def test_ar_printf(self):
        """tests ar command in `.built-in.a.cmd` which follows a `printf | xargs ar` syntax."""
        cmd = 'rm -f built-in.a;  printf "./%s " init/built-in.a usr/built-in.a arch/x86/built-in.a arch/x86/boot/startup/built-in.a kernel/built-in.a certs/built-in.a mm/built-in.a fs/built-in.a ipc/built-in.a security/built-in.a crypto/built-in.a block/built-in.a io_uring/built-in.a lib/built-in.a arch/x86/lib/built-in.a drivers/built-in.a sound/built-in.a net/built-in.a virt/built-in.a arch/x86/pci/built-in.a arch/x86/power/built-in.a arch/x86/video/built-in.a | xargs ar cDPrST built-in.a'
        expected = "init/built-in.a usr/built-in.a arch/x86/built-in.a arch/x86/boot/startup/built-in.a kernel/built-in.a certs/built-in.a mm/built-in.a fs/built-in.a ipc/built-in.a security/built-in.a crypto/built-in.a block/built-in.a io_uring/built-in.a lib/built-in.a arch/x86/lib/built-in.a drivers/built-in.a sound/built-in.a net/built-in.a virt/built-in.a arch/x86/pci/built-in.a arch/x86/power/built-in.a arch/x86/video/built-in.a"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    def test_ar_printf_nested(self):
        """tests ar command in `arch/x86/pci/.built-in.a.cmd` which follows a `printf | xargs ar` syntax."""
        cmd = 'rm -f arch/x86/pci/built-in.a;  printf "arch/x86/pci/%s " i386.o init.o mmconfig_64.o direct.o mmconfig-shared.o fixup.o acpi.o legacy.o irq.o common.o early.o bus_numa.o amd_bus.o | xargs ar cDPrST arch/x86/pci/built-in.a'
        expected = "i386.o init.o mmconfig_64.o direct.o mmconfig-shared.o fixup.o acpi.o legacy.o irq.o common.o early.o bus_numa.o amd_bus.o"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    def test_ar_llvm(self):
        cmd = "llvm-ar mPiT $$(llvm-ar t vmlinux.a | sed -n 1p) vmlinux.a $$(llvm-ar t vmlinux.a | grep -F -f ../scripts/head-object-list.txt)"
        expected = []
        self.assertEqual(parse_commands(cmd), expected)

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
        expected = [Path("../arch/x86/pci/i386.c")]
        self.assertEqual(parse_commands(cmd), expected)

    def test_clang(self):
        cmd = """clang -Wp,-MMD,arch/x86/entry/.entry_64_compat.o.d -nostdinc -I../arch/x86/include -I./arch/x86/include/generated -I../include -I./include -I../arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I../include/uapi -I./include/generated/uapi -include ../include/linux/compiler-version.h -include ../include/linux/kconfig.h -D__KERNEL__ --target=x86_64-linux-gnu -fintegrated-as -Werror=unknown-warning-option -Werror=ignored-optimization-argument -Werror=option-ignored -Werror=unused-command-line-argument -fmacro-prefix-map=../= -Werror -D__ASSEMBLY__ -fno-PIE -m64 -I../arch/x86/entry -Iarch/x86/entry    -DKBUILD_MODFILE='"arch/x86/entry/entry_64_compat"' -DKBUILD_MODNAME='"entry_64_compat"' -D__KBUILD_MODNAME=kmod_entry_64_compat -c -o arch/x86/entry/entry_64_compat.o ../arch/x86/entry/entry_64_compat.S"""
        expected = [Path("../arch/x86/entry/entry_64_compat.S")]
        self.assertEqual(parse_commands(cmd), expected)

    # test rustc

    def test_rustc(self):
        cmd = """OBJTREE=/workspace/linux/kernel_build rustc -Zbinary_dep_depinfo=y -Astable_features -Dnon_ascii_idents -Dunsafe_op_in_unsafe_fn -Wmissing_docs -Wrust_2018_idioms -Wclippy::all -Wclippy::as_ptr_cast_mut -Wclippy::as_underscore -Wclippy::cast_lossless -Wclippy::ignored_unit_patterns -Wclippy::mut_mut -Wclippy::needless_bitwise_bool -Aclippy::needless_lifetimes -Wclippy::no_mangle_with_rust_abi -Wclippy::ptr_as_ptr -Wclippy::ptr_cast_constness -Wclippy::ref_as_ptr -Wclippy::undocumented_unsafe_blocks -Wclippy::unnecessary_safety_comment -Wclippy::unnecessary_safety_doc -Wrustdoc::missing_crate_level_docs -Wrustdoc::unescaped_backticks -Cpanic=abort -Cembed-bitcode=n -Clto=n -Cforce-unwind-tables=n -Ccodegen-units=1 -Csymbol-mangling-version=v0 -Crelocation-model=static -Zfunction-sections=n -Wclippy::float_arithmetic --target=./scripts/target.json -Ctarget-feature=-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-avx,-avx2 -Zcf-protection=branch -Zno-jump-tables -Ctarget-cpu=x86-64 -Ztune-cpu=generic -Cno-redzone=y -Ccode-model=kernel -Zfunction-return=thunk-extern -Zpatchable-function-entry=16,16 -Copt-level=2 -Cdebug-assertions=n -Coverflow-checks=y -Dwarnings @./include/generated/rustc_cfg --edition=2021 --cfg no_fp_fmt_parse --emit=dep-info=rust/.core.o.d --emit=obj=rust/core.o --emit=metadata=rust/libcore.rmeta --crate-type rlib -L./rust --crate-name core /usr/lib/rust-1.84/lib/rustlib/src/rust/library/core/src/lib.rs --sysroot=/dev/null ;llvm-objcopy --redefine-sym __addsf3=__rust__addsf3 --redefine-sym __eqsf2=__rust__eqsf2 --redefine-sym __extendsfdf2=__rust__extendsfdf2 --redefine-sym __gesf2=__rust__gesf2 --redefine-sym __lesf2=__rust__lesf2 --redefine-sym __ltsf2=__rust__ltsf2 --redefine-sym __mulsf3=__rust__mulsf3 --redefine-sym __nesf2=__rust__nesf2 --redefine-sym __truncdfsf2=__rust__truncdfsf2 --redefine-sym __unordsf2=__rust__unordsf2 --redefine-sym __adddf3=__rust__adddf3 --redefine-sym __eqdf2=__rust__eqdf2 --redefine-sym __ledf2=__rust__ledf2 --redefine-sym __ltdf2=__rust__ltdf2 --redefine-sym __muldf3=__rust__muldf3 --redefine-sym __unorddf2=__rust__unorddf2 --redefine-sym __muloti4=__rust__muloti4 --redefine-sym __multi3=__rust__multi3 --redefine-sym __udivmodti4=__rust__udivmodti4 --redefine-sym __udivti3=__rust__udivti3 --redefine-sym __umodti3=__rust__umodti3 rust/core.o"""
        expected = [Path("/usr/lib/rust-1.84/lib/rustlib/src/rust/library/core/src/lib.rs"), Path("rust/core.o")]
        self.assertEqual(parse_commands(cmd), expected)

    # .sh script command tests

    def test_syscallhdr(self):
        """tests syscallhdr.sh command in `arch/x86/include/generated/uapi/asm/.unistd_64.h.cmd`"""
        cmd = "sh ../scripts/syscallhdr.sh --abis common,64 --emit-nr   ../arch/x86/entry/syscalls/syscall_64.tbl arch/x86/include/generated/uapi/asm/unistd_64.h"
        expected = [Path("../arch/x86/entry/syscalls/syscall_64.tbl")]
        self.assertEqual(parse_commands(cmd), expected)

    def test_syscalltbl(self):
        """tests syscalltbl.sh command in `arch/x86/include/generated/asm/.syscalls_64.h.cmd`"""
        cmd = "sh ../scripts/syscalltbl.sh --abis common,64 ../arch/x86/entry/syscalls/syscall_64.tbl arch/x86/include/generated/asm/syscalls_64.h"
        expected = [Path("../arch/x86/entry/syscalls/syscall_64.tbl")]
        self.assertEqual(parse_commands(cmd), expected)

    def test_mkcapflags(self):
        cmd = "sh ../arch/x86/kernel/cpu/mkcapflags.sh arch/x86/kernel/cpu/capflags.c ../arch/x86/kernel/cpu/../../include/asm/cpufeatures.h ../arch/x86/kernel/cpu/../../include/asm/vmxfeatures.h ../arch/x86/kernel/cpu/mkcapflags.sh FORCE"
        expected = "../arch/x86/kernel/cpu/../../include/asm/cpufeatures.h ../arch/x86/kernel/cpu/../../include/asm/vmxfeatures.h"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    def test_orc_hash(self):
        cmd = "mkdir -p arch/x86/include/generated/asm/; sh ../scripts/orc_hash.sh < ../arch/x86/include/asm/orc_types.h > arch/x86/include/generated/asm/orc_hash.h"
        expected = [Path("../arch/x86/include/asm/orc_types.h")]
        self.assertEqual(parse_commands(cmd), expected)

    def test_xen_hypercalls(self):
        cmd = "sh '../scripts/xen-hypercalls.sh' arch/x86/include/generated/asm/xen-hypercalls.h ../include/xen/interface/xen-mca.h ../include/xen/interface/xen.h ../include/xen/interface/xenpmu.h"
        expected = "../include/xen/interface/xen-mca.h ../include/xen/interface/xen.h ../include/xen/interface/xenpmu.h"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # custom cli tool tests

    def test_vdso2c(self):
        cmd = "arch/x86/entry/vdso/vdso2c arch/x86/entry/vdso/vdso64.so.dbg arch/x86/entry/vdso/vdso64.so arch/x86/entry/vdso/vdso-image-64.c"
        expected = "arch/x86/entry/vdso/vdso64.so.dbg arch/x86/entry/vdso/vdso64.so"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    def test_genheaders(self):
        cmd = "security/selinux/genheaders security/selinux/flask.h security/selinux/av_permissions.h"
        expected = "security/selinux/include/classmap.h security/selinux/include/initial_sid_to_string.h"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # ld command tests

    def test_ld(self):
        cmd = 'ld -o arch/x86/entry/vdso/vdso64.so.dbg -shared --hash-style=both --build-id=sha1 --no-undefined  --eh-frame-hdr -Bsymbolic -z noexecstack -m elf_x86_64 -soname linux-vdso.so.1 -z max-page-size=4096 -T arch/x86/entry/vdso/vdso.lds arch/x86/entry/vdso/vdso-note.o arch/x86/entry/vdso/vclock_gettime.o arch/x86/entry/vdso/vgetcpu.o arch/x86/entry/vdso/vgetrandom.o arch/x86/entry/vdso/vgetrandom-chacha.o; if readelf -rW arch/x86/entry/vdso/vdso64.so.dbg | grep -v _NONE | grep -q " R_\w*_"; then (echo >&2 "arch/x86/entry/vdso/vdso64.so.dbg: dynamic relocations are not supported"; rm -f arch/x86/entry/vdso/vdso64.so.dbg; /bin/false); fi'  # type: ignore
        expected = "arch/x86/entry/vdso/vdso-note.o arch/x86/entry/vdso/vclock_gettime.o arch/x86/entry/vdso/vgetcpu.o arch/x86/entry/vdso/vgetrandom.o arch/x86/entry/vdso/vgetrandom-chacha.o"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # sed command tests

    def test_sed(self):
        cmd = "sed -n 's/.*define *BLIST_\\([A-Z0-9_]*\\) *.*/BLIST_FLAG_NAME(\\1),/p' ../include/scsi/scsi_devinfo.h > drivers/scsi/scsi_devinfo_tbl.c"
        expected = "../include/scsi/scsi_devinfo.h"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # nm command tests

    def test_nm(self):
        cmd = """llvm-nm -p --defined-only rust/core.o | awk '$$2~/(T|R|D|B)/ && $$3!~/__(pfx|cfi|odr_asan)/ { printf "EXPORT_SYMBOL_RUST_GPL(%s);\n",$$3 }' > rust/exports_core_generated.h"""
        expected = "rust/core.o"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # pnmtologo tests

    def test_pnmtologo(self):
        cmd = "drivers/video/logo/pnmtologo -t clut224 -n logo_linux_clut224 -o drivers/video/logo/logo_linux_clut224.c ../drivers/video/logo/logo_linux_clut224.ppm"
        expected = "../drivers/video/logo/logo_linux_clut224.ppm"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # perl tests

    def test_perl(self):
        cmd = "perl ../lib/crypto/x86/poly1305-x86_64-cryptogams.pl > lib/crypto/x86/poly1305-x86_64-cryptogams.S"
        expected = "../lib/crypto/x86/poly1305-x86_64-cryptogams.pl"
        self.assertEqual(parse_commands(cmd), [Path(p) for p in expected.split(" ")])

    # polgen tests

    def test_polgen(self):
        cmd = "scripts/ipe/polgen/polgen security/ipe/boot_policy.c"
        expected = []
        self.assertEqual(parse_commands(cmd), expected)

    # manual file creation tests

    def test_manual_file_creation(self):
        cmd = """{ symbase=__dtbo_overlay_bad_unresolved; echo '$(pound)include <asm-generic/vmlinux.lds.h>'; echo '.section .rodata,"a"'; echo '.balign STRUCT_ALIGNMENT'; echo ".global $${symbase}_begin"; echo "$${symbase}_begin:"; echo '.incbin "drivers/of/unittest-data/overlay_bad_unresolved.dtbo" '; echo ".global $${symbase}_end"; echo "$${symbase}_end:"; echo '.balign STRUCT_ALIGNMENT'; } > drivers/of/unittest-data/overlay_bad_unresolved.dtbo.S"""
        expected = []
        self.assertEqual(parse_commands(cmd), expected)


if __name__ == "__main__":
    unittest.main()
