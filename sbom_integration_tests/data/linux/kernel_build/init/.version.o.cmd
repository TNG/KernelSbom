# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

savedcmd_init/version.o := gcc -c -o init/version.o ../init/version.c

source_init/version.o := ../init/version.c

deps_init/version.o := \
  ../init/version.c \

init/version.o: $(deps_init/version.o)

$(deps_init/version.o):
