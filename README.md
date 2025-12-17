<!--
SPDX-License-Identifier: GPL-2.0-only OR MIT
SPDX-FileCopyrightText: 2025 TNG Technology Consulting GmbH
-->

# KernelSbom

A script to generate an SPDX-format Software Bill of Materials (SBOM) for the linux kernel build.
The eventual goal is to integrate the `sbom/` directory into the `linux/tools/` directory in the official [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) source tree.

## How to use
1. Provide a linux source and object tree, e.g., by downloading precompiled test data from [KernelSbom-TestData](https://fileshare.tngtech.com/d/e69946da808b41f88047/files)
    ```bash
    test_archive="linux.v6.17.tinyconfig.x86.tar.gz"
    curl -L -o "$test_archive" "https://fileshare.tngtech.com/d/e69946da808b41f88047/files/?p=%2F$test_archive&dl=1"
    tar -xzf "$test_archive"
    ```
    or cloning the [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) repo and building your own config
    ```bash
    git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
    cd linux
    make <config> O=kernel_build
    make -j$(nproc) O=kernel_build
    ```
2. Clone the repository 
    ```
    git clone git@github.com:TNG/KernelSbom.git
    cd KernelSbom
    ```
3. Run the [sbom.py](sbom/sbom.py) script
    ```bash
    SRCARCH=x86 python3 sbom/sbom.py \
      --src-tree ../linux \
      --obj-tree ../linux/kernel_build \
      --roots arch/x86/boot/bzImage \
      --generate-spdx \
      --generate-used-files \
      --prettify-json \
      --debug
    ```

Starting from the provided root artifact (`bzImage`), the script constructs a **cmd graph**: a directed acyclic graph whose nodes are filenames and whose edges represent build dependencies extracted from the corresponding `.<filename>.cmd` files.

Using this cmd graph, the script generates three SPDX documents and writes them to disk:
- **`sbom-source.spdx.json`** — Describes all source files in the source tree that contributed to building the provided root artifacts (`bzImage`).
- **`sbom-build.spdx.json`** — Describes all build artifacts and the process by which they were built from the sources in `sbom-source.spdx.json`.
- **`sbom-output.spdx.json`** — Describes the final build outputs, i.e., the provided root artifacts.

If the `--generate-used-files` flag is enabled, the script also produces **`sbom.used-files.txt`**, a flat list of all source files in `sbom-source.spdx.json`.

**Note:** If the source tree and object tree are identical, reliably distinguishing source files is not possible. In this case, the source SPDX document is merged into `sbom-build.spdx.json`, and `sbom.used-files.txt` contains all files from `sbom-build.spdx.json`.

### Kernel Modules

To include `.ko` kernel modules in the provided root artifacts, you can use the helper script below to generate a `roots.txt` file:

```bash
echo "arch/x86/boot/bzImage" >> roots.txt
sed 's/\.o$/.ko/' <obj_tree>/modules.order >> roots.txt
```
Then pass the roots file to the main script:
```bash
SRCARCH=x86 python3 sbom/sbom.py \
  --src-tree ../linux \
  --obj-tree ../linux/kernel_build \
  --roots-file roots.txt \
  --generate-spdx \
  --generate-used-files \
  --prettify-json
```

## SPDX Graph Visualization

The following diagrams illustrate the structure of the generated SPDX documents: `sbom-source.spdx.json`, `sbom-build.spdx.json`, and `sbom-output.spdx.json`.

### Separate Source and Object Trees
```mermaid
flowchart TD

    %% SHARED ELEMENTS
    AGENT["SoftwareAgent"]
    CREATION_INFO["CreationInfo"]

    CREATION_INFO -->|createdBy| AGENT

    %% SPDX DOCUMENTS
    subgraph SOURCE_GRAPH["sbom-source.spdx.json"]
        SOURCE_DOC["SpdxDocument"]
        SOURCE_SBOM["Sbom"]
        SOURCE_TREE["File (src_tree)"]
        MAINC["File (init/main.c)"]
        GPL2ONLY_LICENSEEXPRESSION["LicenseExpression (GPL-2.0-only)"]

        SOURCE_DOC -->|rootElement| SOURCE_SBOM

        SOURCE_SBOM -->|rootElement| SOURCE_TREE
        SOURCE_SBOM -->|element| SOURCE_TREE
        SOURCE_SBOM -->|element| MAINC
        SOURCE_SBOM -->|element| GPL2ONLY_LICENSEEXPRESSION

        SOURCE_TREE -->|contains| MAINC

        MAINC -->|hasDeclaredLicense| GPL2ONLY_LICENSEEXPRESSION
    end

    subgraph OUTPUT_GRAPH["sbom-output.spdx.json"]
        OUTPUT_DOC["SpdxDocument"]
        OUTPUT_SBOM["Sbom"]
        PACKAGE["Package (Linux Kernel (bzImage))"]
        PACKAGE_LICENSEEXPRESSION["LicenseExpression (GPL-2.0 WITH Linux-syscall-note)"]
        HIGH_LEVEL_BUILD["Build (High Level)"]
        CONFIG["File (.config)"]
        BZIMAGE["File (arch/x86/boot/bzImage)"]

        OUTPUT_DOC -->|rootElement| OUTPUT_SBOM

        OUTPUT_SBOM -->|rootElement| PACKAGE
        OUTPUT_SBOM -->|element| PACKAGE
        OUTPUT_SBOM -->|element| BZIMAGE
        OUTPUT_SBOM -->|element| PACKAGE_LICENSEEXPRESSION
        OUTPUT_SBOM -->|element| HIGH_LEVEL_BUILD
        OUTPUT_SBOM -->|element| CONFIG

        HIGH_LEVEL_BUILD -->|configSourceUri| CONFIG

        PACKAGE -->|hasDistributionArtifact| BZIMAGE
        PACKAGE -->|hasDeclaredLicense| PACKAGE_LICENSEEXPRESSION

    end

    PACKAGE -->|originatedBy| AGENT

    subgraph BUILD_GRAPH["sbom-build.spdx.json"]
        BUILD_DOC["SpdxDocument"]
        BUILD_SBOM["Sbom"]
        LOW_LEVEL_BUILD["Build"]

        OBJ_TREE["File (obj_tree)"]
        VMLINUX_BIN["File (arch/x86/boot/vmlinux.bin)"]
        DOTDOT["..."]
        RUSTLIB["File (sources outside of src tree, e.g., rustlib/src/rust/library/core/src/lib.rs)"]
        
        MAINC_EXTERNALMAP["ExternalMap (init/main.c)"]
        BZIMAGE_EXTERNALMAP["ExternalMap (arch/x86/boot/bzImage)"]
        HIGH_LEVEL_BUILD_EXTERNALMAP["ExternalMap<br>(Build (High Level))"]
      
        
        BUILD_DOC -->|rootElement| BUILD_SBOM
        BUILD_DOC -->|import| MAINC_EXTERNALMAP
        BUILD_DOC -->|import| BZIMAGE_EXTERNALMAP
        BUILD_DOC -->|import| HIGH_LEVEL_BUILD_EXTERNALMAP

        BUILD_SBOM -->|rootElement| OBJ_TREE
        BUILD_SBOM -->|element| OBJ_TREE
        BUILD_SBOM -->|element| RUSTLIB
        BUILD_SBOM -->|element| VMLINUX_BIN
        BUILD_SBOM -->|element| BZIMAGE
        BUILD_SBOM -->|element| LOW_LEVEL_BUILD

        OBJ_TREE -->|contains| VMLINUX_BIN
        OBJ_TREE -->|contains| BZIMAGE

        HIGH_LEVEL_BUILD -->|ancestorOf| LOW_LEVEL_BUILD
        
        MAINC -.->|Build| DOTDOT
        RUSTLIB -.->|Build| DOTDOT
        DOTDOT -.->|Build| VMLINUX_BIN
        LOW_LEVEL_BUILD -->|hasInput| VMLINUX_BIN
        VMLINUX_BIN -.->|Build| LOW_LEVEL_BUILD
        LOW_LEVEL_BUILD -->|hasOutput| BZIMAGE
        LOW_LEVEL_BUILD -.->|Build| BZIMAGE

    end
```

### Equal Source and Object Trees

```mermaid
flowchart TD

    %% SHARED ELEMENTS
    AGENT["SoftwareAgent"]
    CREATION_INFO["CreationInfo"]

    CREATION_INFO -->|createdBy| AGENT

    subgraph OUTPUT_GRAPH["sbom-output.spdx.json"]
        OUTPUT_DOC["SpdxDocument"]
        OUTPUT_SBOM["Sbom"]
        PACKAGE["Package (Linux Kernel (bzImage))"]

        BZIMAGE["File (arch/x86/boot/bzImage)"]
        HIGH_LEVEL_BUILD["Build (High Level)"]
        CONFIG["File (.config)"]
      
        PACKAGE_LICENSEEXPRESSION["LicenseExpression (GPL-2.0 WITH Linux-syscall-note)"]
     
        OUTPUT_DOC -->|rootElement| OUTPUT_SBOM

        OUTPUT_SBOM -->|rootElement| PACKAGE
        OUTPUT_SBOM -->|element| PACKAGE
        OUTPUT_SBOM -->|element| PACKAGE_LICENSEEXPRESSION
        OUTPUT_SBOM -->|element| BZIMAGE
        OUTPUT_SBOM -->|element| HIGH_LEVEL_BUILD
        OUTPUT_SBOM -->|element| CONFIG 

        HIGH_LEVEL_BUILD -->|configSourceUri| CONFIG

        PACKAGE -->|hasDistributionArtifact| BZIMAGE
        PACKAGE -->|hasDeclaredLicense| PACKAGE_LICENSEEXPRESSION
    end

    PACKAGE -->|originatedBy| AGENT

    %% SPDX DOCUMENTS
    subgraph BUILD_GRAPH["sbom-build.spdx.json"]
        BUILD_DOC["SpdxDocument"]
        BUILD_SBOM["Sbom"]
        BZIMAGE_EXTERNALMAP["ExternalMap (arch/x86/boot/bzImage)"]
        HIGH_LEVEL_BUILD_EXTERNALMAP["ExternalMap<br>(Build (High Level))"]
        LOW_LEVEL_BUILD["Build"]
        MAINC["File (init/main.c)"]
        GPL2ONLY_LICENSEEXPRESSION["LicenseExpression (GPL-2.0-only)"]
        VMLINUX_BIN["File (arch/x86/boot/vmlinux.bin)"]
        DOTDOT["..."]
        RUSTLIB["File (sources outside of src tree, e.g., rustlib/src/rust/library/core/src/lib.rs)"]
        
        BUILD_DOC -->|rootElement| BUILD_SBOM
        BUILD_DOC -->|import| BZIMAGE_EXTERNALMAP
        BUILD_DOC -->|import| HIGH_LEVEL_BUILD_EXTERNALMAP

        BUILD_SBOM -->|rootElement| BZIMAGE
        BUILD_SBOM -->|element| RUSTLIB
        BUILD_SBOM -->|element| MAINC
        BUILD_SBOM -->|element| GPL2ONLY_LICENSEEXPRESSION
        BUILD_SBOM -->|element| VMLINUX_BIN
        BUILD_SBOM -->|element| LOW_LEVEL_BUILD

        HIGH_LEVEL_BUILD -->|ancestorOf| LOW_LEVEL_BUILD

        MAINC -.->|Build| DOTDOT
        RUSTLIB -.->|Build| DOTDOT
        DOTDOT -.->|Build| VMLINUX_BIN
        VMLINUX_BIN -.->|Build| LOW_LEVEL_BUILD
        LOW_LEVEL_BUILD -->|hasInput| VMLINUX_BIN
        LOW_LEVEL_BUILD -->|hasOutput| BZIMAGE
        LOW_LEVEL_BUILD -.->|Build| BZIMAGE
        MAINC -->|hasDeclaredLicense| GPL2ONLY_LICENSEEXPRESSION
    end
    
```


## Directory Structure

- `sbom/`
  - `sbom.py` - The main script responsible for generating the SBOM
  - `sbom/sbom/` - Library modules used by the main script
  - `sbom/tests/` - Unit tests for the library modules
- `sbom_analysis/` - Additional scripts for analyzing the outputs produced by the main script.
  - [sbom_analysis/cmd_graph_based_kernel_build/](sbom_analysis/cmd_graph_based_kernel_build/README.md) - Validation of cmd graph completeness by rebuilding the linux kernel only with files referenced in the cmd graph.
  - [sbom_analysis/cmd_graph_visualization/](sbom_analysis/cmd_graph_visualization/README.md) - Interactive visualization of the cmd graph
  - [sbom_analysis/strace_kernel_build/](sbom_analysis/strace_kernel_build/README.md) - build kernel with strace and compare touched files with files found with cmd graph
- `testdata_generation/` - Describes how the precompiled kernel builds in [KernelSbom-TestData](https://fileshare.tngtech.com/library/98e7e6f8-bffe-4a55-a8d2-817d4f3e51e8/KernelSbom-TestData/) were generated.

The main contribution of this repository is the content of the `sbom` directory which eventually should be moved into the `linux/tools/` directory in the official [linux](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git) source tree.

## Development

Activate the venv and install build dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pre-commit reuse ruff
pre-commit install
```

When committing, `reuse lint` is run as a pre-commit hook to ensure all files have compliant license headers.  
If any file is missing a license header, it can be added using:
```
reuse annotate --license="GPL-2.0-only OR MIT" --copyright="TNG Technology Consulting GmbH" --template default <filename>
```
> **Note:** If the annotated file contains a shebang, `reuse annotate` will insert an empty line after it. This empty line must be removed manually.

## Run tests
Unit tests can be found in `sbom/tests`. These are designed to be contributed upstream to the `linux` kernel repository.
Integration tests are located in `sbom_integration_tests`. These tests are not intended for inclusion in the kernel repository, as they require a larger number of additional files.

```bash
# Run unit tests
python3 -m unittest discover -v -s sbom -p "test_*.py"
# Run integration tests
python3 -m unittest discover -v -s sbom_integration_tests -p "test_*.py"
```
