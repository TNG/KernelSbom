# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

import os
from pathlib import Path
import re
import sys


def get_module_roots(modules_path: Path) -> list[Path]:
    """
    Parse a modules.order style file and return normalized '.ko' module paths.

    Args:
        modules_path (Path): Path to a file listing module object files (.o) or module kernel object files (.ko) directly.

    Returns:
        module_roots (list[Path]): Normalized paths to corresponding '.ko' modules.
    """
    with open(modules_path, "r") as f:
        modules = [Path(module.strip()) for module in f.readlines()]
    return [Path(os.path.normpath(module.parent / re.sub(r"\.o$", ".ko", module.name))) for module in modules]


if __name__ == "__main__":
    """
    module_roots.py <modules_path> <output_path>
    """
    script_path = Path(__file__).parent
    modules_path = (
        Path(sys.argv[1]) if sys.argv[1] else (script_path / "../../../linux/kernel_build/modules.order").resolve()
    )
    output_path = sys.argv[2] if sys.argv[2] else Path.cwd() / "module_roots.txt"

    module_roots = get_module_roots(modules_path)
    with open(output_path, "wt") as f:
        f.write("\n".join(str(module_root) for module_root in module_roots))
    print(f"Successfully Saved module roots in '{output_path}'")
