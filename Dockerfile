FROM ubuntu:22.04
RUN apt-get update && \
    apt-get install -y \
        build-essential linux-headers-generic bc \
        flex bison python3 git libelf-dev libssl-dev 
WORKDIR /workspace
RUN git clone https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
RUN cd linux && \
    make defconfig O=kernel-build && \
    make -j$(nproc) O=kernel-build