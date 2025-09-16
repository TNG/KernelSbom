# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH <info@tngtech.com>
#
# SPDX-License-Identifier: GPL-2.0-only

import unittest

from lib.sbom.cmd.savedcmd_parser import parse_savedcmd

class TestHelloWorld(unittest.TestCase):
    def test_objcopy(self):
        cmd = "objcopy --remove-section='.rel*' --remove-section=!'.rel*.dyn' vmlinux.unstripped vmlinux"
        expected = ["vmlinux.unstripped"]
        self.assertEqual(parse_savedcmd(cmd), expected)

    def test_link_vmlinux(self):
        cmd = '../scripts/link-vmlinux.sh "ld" "-m elf_x86_64 -z noexecstack" "-z max-page-size=0x200000 --build-id=sha1 --orphan-handling=error --emit-relocs --discard-none" "vmlinux.unstripped";  true'
        expected = ["vmlinux.a"]
        self.assertEqual(parse_savedcmd(cmd), expected)
    
    def test_ar(self):
        cmd = 'rm -f vmlinux.a; ar cDPrST vmlinux.a built-in.a  lib/lib.a arch/x86/lib/lib.a; ar mPiT $$(ar t vmlinux.a | sed -n 1p) vmlinux.a $$(ar t vmlinux.a | grep -F -f ../scripts/head-object-list.txt)'
        expected = ["built-in.a", "lib/lib.a", "arch/x86/lib/lib.a"]
        self.assertEqual(parse_savedcmd(cmd), expected)

    def test_ar2(self):
        cmd = 'rm -f built-in.a;  printf "./%s " init/built-in.a usr/built-in.a arch/x86/built-in.a arch/x86/boot/startup/built-in.a kernel/built-in.a certs/built-in.a mm/built-in.a fs/built-in.a ipc/built-in.a security/built-in.a crypto/built-in.a block/built-in.a io_uring/built-in.a lib/built-in.a arch/x86/lib/built-in.a drivers/built-in.a sound/built-in.a net/built-in.a virt/built-in.a arch/x86/pci/built-in.a arch/x86/power/built-in.a arch/x86/video/built-in.a | xargs ar cDPrST built-in.a'
        expected = ['init/built-in.a', 'usr/built-in.a', 'arch/x86/built-in.a', 'arch/x86/boot/startup/built-in.a', 'kernel/built-in.a', 'certs/built-in.a', 'mm/built-in.a', 'fs/built-in.a', 'ipc/built-in.a', 'security/built-in.a', 'crypto/built-in.a', 'block/built-in.a', 'io_uring/built-in.a', 'lib/built-in.a', 'arch/x86/lib/built-in.a', 'drivers/built-in.a', 'sound/built-in.a', 'net/built-in.a', 'virt/built-in.a', 'arch/x86/pci/built-in.a', 'arch/x86/power/built-in.a', 'arch/x86/video/built-in.a']
        self.assertEqual(parse_savedcmd(cmd), expected)

if __name__ == '__main__':
    unittest.main()
