#!/bin/sh

set -e -x

# Kernel Source
KERNEL_SOURCE="https://github.com/rdbckp/kernel_a02"
KERNEL_BRANCH="kernelku"
KERNEL_DEFCONFIG="a02_defconfig"

# Prebuilt Clang Toolchain (AOSP)
CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android12L-s1-release/clang-r416183b1.tar.gz"
# CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/master-kernel-build-2021/clang-r383902.tar.gz"
# CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android11-qpr3-s1-release/clang-r383902b1.tar.gz"
# CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android12-qpr3-s7-release/clang-r383902.tar.gz"
# CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android12-gsi/clang-r383902.tar.gz"
# CLANG_URL="https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86/+archive/refs/heads/android12-release/clang-r416183b1.tar.gz"
# CLANG_URL="https://github.com/SayuZX/android_prebuilts_clang_host_linux-x86_clang-r437112.git"
# CLANG_BRANCH="master"
# CLANG_URL="https://github.com/LineageOS/android_prebuilts_clang_kernel_linux-x86_clang-r416183b.git"
# CLANG_BRANCH="lineage-20.0"

# Prebuilt GCC Utilities (AOSP)
GCC_URL="https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.9/+archive/refs/heads/android12L-s1-release.tar.gz"
# GCC_URL="https://github.com/EternalX-project/arm-linux-gnueabi.git"
# GCC_BRANCH="amd64"
# GCC_URL="https://github.com/LineageOS/android_prebuilts_gcc_linux-x86_arm_arm-linux-androideabi-4.9.git"
# GCC_BRANCH="lineage-19.1"

# Setup make Command
make_fun() {
	make O=out ARCH=arm CC=clang HOSTCC=clang \
		CLANG_TRIPLE=arm-linux-gnueabi- \
		CROSS_COMPILE=arm-linux-androidkernel- "$@"
}

# Work Path
WORK="${HOME}/work"

# Kernel Folder Name
KERNEL="myKernel"

# Kernel Source Path
KERNEL_SRC="${WORK}/${KERNEL}"

# Prepare Directory
mkdir -p "${WORK}"
cd "${WORK}" || exit 1

# Cloning all the Necessary files
if [ ! -d clang ]; then mkdir clang && curl -Lsq "${CLANG_URL}" -o clang.tgz && tar -xzf clang.tgz -C clang; fi
if [ ! -d gcc ]; then mkdir gcc && curl -Lsq "${GCC_URL}" -o gcc.tgz && tar -xzf gcc.tgz -C gcc; fi
# if [ ! -d gcc ]; then mkdir gcc && curl -Lsq "${GCC_URL}" -o gcc.tar.xz && unxz gcc.tar.xz && tar -xvf gcc.tar -C gcc; fi
# [ ! -d clang ] && git clone --depth=1 "${CLANG_URL}" -b "${CLANG_BRANCH}" ./clang
# [ ! -d gcc ] && git clone --depth=1 "${GCC_URL}" -b "${GCC_BRANCH}" ./gcc
[ ! -d "${KERNEL}" ] && git clone --depth=1 "${KERNEL_SOURCE}" -b "${KERNEL_BRANCH}" "${KERNEL}"

# Setting Toolchain Path
PATH="${WORK}/clang/bin:${WORK}/gcc/bin:/bin"

# Enter Kernel root directory
cd "${KERNEL_SRC}" || exit 1

# Start Compiling Kernel
make_fun "${KERNEL_DEFCONFIG}"
make_fun -j"$(nproc --all)" 2>&1 | tee build.log 
