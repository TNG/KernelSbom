# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

savedcmd_arch/x86/boot/bzImage := (dd if=arch/x86/boot/setup.o bs=4k conv=sync status=none; cat arch/x86/boot/main.o) >arch/x86/boot/bzImage

source_arch/x86/boot/bzImage := arch/x86/boot/main.o

deps_arch/x86/boot/bzImage := \
  arch/x86/boot/main.o \
  arch/x86/boot/setup.o \
  init/built-in.a \

arch/x86/boot/bzImage: $(deps_arch/x86/boot/bzImage)

$(deps_arch/x86/boot/bzImage):
