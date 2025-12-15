#!/bin/sh

set -e -x

# custom toolchain preparation
cd ${GITHUB_WORKSPACE}
ls
export PATH="${PWD}/toolchain2/clang/bin:${PWD}/toolchain2/gcc/bin:${PATH}"

# export PATH="${PWD}/toolchain/clang/bin:${PWD}/toolchain/gcc/bin:${PATH}"
export ARCH=arm
export CC=clang
export HOSTCC=clang
export CLANG_TRIPLE=arm-linux-gnueabi-
export CROSS_COMPILE=arm-linux-androideabi-
export KCFLAGS=-w
export CONFIG_SECTION_MISMATCH_WARN_ONLY=y
rm -rf out
mkdir -p out

make O=out KCFLAGS=-w CONFIG_SECTION_MISMATCH_WARN_ONLY=y ARCH=arm CC=clang HOSTCC=clang CLANG_TRIPLE=arm-linux-gnueabi- CROSS_COMPILE=arm-linux-androidkernel- clean
make O=out KCFLAGS=-w CONFIG_SECTION_MISMATCH_WARN_ONLY=y ARCH=arm CC=clang HOSTCC=clang CLANG_TRIPLE=arm-linux-gnueabi- CROSS_COMPILE=arm-linux-androidkernel- mrproper
make O=out KCFLAGS=-w CONFIG_SECTION_MISMATCH_WARN_ONLY=y ARCH=arm CC=clang HOSTCC=clang CLANG_TRIPLE=arm-linux-gnueabi- CROSS_COMPILE=arm-linux-androidkernel- a02_defconfig
make O=out KCFLAGS=-w CONFIG_SECTION_MISMATCH_WARN_ONLY=y ARCH=arm CC=clang HOSTCC=clang CLANG_TRIPLE=arm-linux-gnueabi- CROSS_COMPILE=arm-linux-androidkernel- -j16

cp out/arch/arm/boot/zImage ${PWD}/zImage
mv zImage boot.img-kernel
