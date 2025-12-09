# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import os
import re
import sys


def get_module_roots(modules_path: str) -> list[str]:
    """
    Parse a modules.order style file and return normalized '.ko' module paths.

    Args:
        modules_path (str): Path to a file listing module object files (.o) or module kernel object files (.ko) directly.

    Returns:
        module_roots (list[str]): Normalized paths to corresponding '.ko' modules.
    """
    with open(modules_path, "r") as f:
        modules = [module.strip() for module in f.readlines()]
    return [os.path.normpath(re.sub(r"\.o$", ".ko", module)) for module in modules]


if __name__ == "__main__":
    """
    module_roots.py <modules_path> <output_path>
    """
    script_path = os.path.dirname(__file__)
    modules_path = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.path.normpath(os.path.join(script_path, "../../../linux/kernel_build/modules.order"))
    )
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(os.getcwd(), "module_roots.txt")

    module_roots = get_module_roots(modules_path)

    for module_root in module_roots:
        print(module_root)
