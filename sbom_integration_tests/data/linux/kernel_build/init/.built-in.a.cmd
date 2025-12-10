# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

savedcmd_init/built-in.a := rm -f init/built-in.a;  printf "init/%s " main.o version.o | xargs ar cDPrST init/built-in.a
