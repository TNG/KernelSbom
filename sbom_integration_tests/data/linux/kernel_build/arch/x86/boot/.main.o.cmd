# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

savedcmd_arch/x86/boot/main.o := gcc -c -o arch/x86/boot/main.o ../arch/x86/boot/main.c

source_arch/x86/boot/main.o := ../arch/x86/boot/main.c

deps_arch/x86/boot/main.o := \
  ../arch/x86/boot/main.c \

arch/x86/boot/main.o: $(deps_arch/x86/boot/main.o)

$(deps_arch/x86/boot/main.o):
