# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import os
from pathlib import Path
import re


def get_module_roots(modules: Path | list[Path]) -> list[Path]:
    """
    Args
        modules: Path | list[Path] Either a path to a file like modules.order which lists all '.o' or '.ko' module roots or a direct list of paths to module roots.

    Returns
        module_roots: list[Path]   list of paths to '.ko' module roots
    """
    if isinstance(modules, Path):
        with open(modules, "r") as f:
            modules = [Path(module.strip()) for module in f.readlines()]
    return [Path(os.path.normpath(module.parent / re.sub(r"\.o$", ".ko", module.name))) for module in modules]
