# SPDX-License-Identifier: GPL-2.0-only OR MIT
# SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH

SBOM_SOURCE_FILE = $(objtree)/sbom-source.spdx.json
SBOM_BUILD_FILE = $(objtree)/sbom-build.spdx.json
SBOM_OUTPUT_FILE = $(objtree)/sbom-output.spdx.json

ifdef O
    SBOM_TARGETS = $(SBOM_SOURCE_FILE) $(SBOM_BUILD_FILE) $(SBOM_OUTPUT_FILE)
else
    SBOM_TARGETS = $(SBOM_BUILD_FILE) $(SBOM_OUTPUT_FILE)
endif

roots := $(shell printf "$(KBUILD_IMAGE)\n"; \
	             sed 's/\.o$$/.ko/' $(objtree)/modules.order)

sbom: $(SBOM_TARGETS)

$(SBOM_TARGETS) &:
	@echo "  GEN     $(notdir $(SBOM_TARGETS))"
	@python3 sbom.py \
      --src-tree ../../.. \
      --obj-tree $(objtree) \
      --roots $(roots) \
      --generate-spdx \
      --output-directory $(objtree) \
      --package-license "GPL-2.0 WITH Linux-syscall-note" \
      --package-version "$(KERNELVERSION)"

.PHONY: sbom
