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

SBOM_DEPS := $(objtree)/$(KBUILD_IMAGE) $(objtree)/include/generated/autoconf.h
ifdef CONFIG_MODULES
    SBOM_DEPS += $(objtree)/modules.order
endif

sbom: $(SBOM_TARGETS)

$(SBOM_TARGETS) &: $(SBOM_DEPS)
	@echo "  GEN     $(notdir $(SBOM_TARGETS))"

	@printf "%s\n" "$(KBUILD_IMAGE)" > $(SBOM_ROOTS_FILE)
	@if [ "$(CONFIG_MODULES)" = "y" ]; then \
		sed 's/\.o$$/.ko/' $(objtree)/modules.order >> $(SBOM_ROOTS_FILE); \
	fi

	@python3 sbom.py \
      --src-tree $(srctree) \
      --obj-tree $(objtree) \
      --roots-file $(SBOM_ROOTS_FILE) \
      --output-directory $(objtree) \
      --generate-spdx \
      --package-license "GPL-2.0 WITH Linux-syscall-note" \
      --package-version "$(KERNELVERSION)"

	@rm $(SBOM_ROOTS_FILE)

.PHONY: sbom
