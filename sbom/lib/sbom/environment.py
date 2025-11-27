# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import os


class Environment:
    ARCH = os.getenv("ARCH", None)
    SRCARCH = os.getenv("SRCARCH", None)
