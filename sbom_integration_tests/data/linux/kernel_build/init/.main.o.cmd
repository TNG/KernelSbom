# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

savedcmd_init/main.o := gcc -c -o init/main.o ../init/main.c

source_init/main.o := ../init/main.c

deps_init/main.o := \
  ../init/main.c \

init/main.o: $(deps_init/main.o)

$(deps_init/main.o):
