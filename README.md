# LinuxKernelSbomGenerator

Example invocation assuming the linux kernel was build via `make -j$(nproc) O=kernel-build`
```
python3 sbom.py \
  --src-tree ../linux \
  --output-tree ../linux/kernel-build \
  --root-outputs vmlinux \
  --output sbom.spdx.json \
  --debug 1
```
