# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

savedcmd_arch/x86/boot/setup.o := gcc -c -o arch/x86/boot/setup.o ../arch/x86/boot/setup.c

source_arch/x86/boot/setup.o := ../arch/x86/boot/setup.c

deps_arch/x86/boot/setup.o := \
  ../arch/x86/boot/setup.c \

arch/x86/boot/setup.o: $(deps_arch/x86/boot/setup.o)

$(deps_arch/x86/boot/setup.o):
