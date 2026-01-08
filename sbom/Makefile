# SPDX-License-Identifier: GPL-2.0-only OR MIT
# Copyright (C) 2025 TNG Technology Consulting GmbH

srctree := $(abspath ../../..)

SBOM_SOURCE_FILE := $(objtree)/sbom-source.spdx.json
SBOM_BUILD_FILE := $(objtree)/sbom-build.spdx.json
SBOM_OUTPUT_FILE := $(objtree)/sbom-output.spdx.json
SBOM_ROOTS_FILE := $(objtree)/sbom-roots.txt


ifeq ($(srctree),$(objtree))
    SBOM_TARGETS := $(SBOM_SOURCE_FILE) $(SBOM_BUILD_FILE) $(SBOM_OUTPUT_FILE)
else
    SBOM_TARGETS := $(SBOM_BUILD_FILE) $(SBOM_OUTPUT_FILE)
endif

sbom: $(SBOM_TARGETS)

$(SBOM_ROOTS_FILE): $(objtree)/modules.order
	@printf "%s\n" "$(KBUILD_IMAGE)" > $@
	@sed 's/\.o$$/.ko/' $(objtree)/modules.order >> $@

$(SBOM_TARGETS) &: $(SBOM_ROOTS_FILE)
	@echo "  GEN     $(notdir $(SBOM_TARGETS))"
	@python3 sbom.py \
      --src-tree $(srctree) \
      --obj-tree $(objtree) \
      --roots-file $(SBOM_ROOTS_FILE) \
      --output-directory $(objtree) \
      --generate-spdx \
      --package-license "GPL-2.0 WITH Linux-syscall-note" \
      --package-version "$(KERNELVERSION)"

.PHONY: sbom
