# LinuxKernelSbomGenerator

Script to generate an SBOM of the `vmlinux` kernel build in the [SPDX](https://github.com/spdx) format. 

To test the script first build the linux kernel out-of-tree into the `kernel-build` directory:
```
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) bc flex bison python3

# compile entire linux kernel (https://kernelnewbies.org/KernelBuild)
cp /boot/config-$(uname -r) kernel-build/.config
make O=kernel-build olddefconfig
make -j$(nproc) O=kernel-build
# build errors might need to be fixed by installing missing dependencies and disabling some configs. For example:
sudo apt install libdwarf-dev libelf-dev libdw-dev libssl-dev gawk
sudo ln -s /usr/include/libdwarf/dwarf.h /usr/include/dwarf.h
scripts/config --file kernel-build/.config --disable SYSTEM_TRUSTED_KEYS
scripts/config --file kernel-build/.config --disable MODULE_SIG
scripts/config --file kernel-build/.config --disable MODULE_SIG_ALL
scripts/config --file kernel-build/.config --disable SYSTEM_REVOCATION_KEYS
```

Next clone this repository next to the `linux` directory that contains the `kernel-build`
```bash
git clone git@github.com:TNG/LinuxKernelSbomGenerator.git`
cd LinuxKernelSbomGenerator
```
Now execute the script via command line
```
python3 sbom.py \
  --src-tree ../linux \
  --output-tree ../linux/kernel-build \
  --root-outputs vmlinux \
  --output sbom.spdx.json \
  --debug 1
```
or debug the script in vscode using the [Python Debugger: sbom](./.vscode/launch.json) launch configuration.