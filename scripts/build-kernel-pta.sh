#!/bin/bash -ve
PROJ_DIR=${PWD}/..
LLVM_BUILD=${PROJ_DIR}/build/bin
BINUTIL=~/util/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/bin
export PATH=${BINUTIL}:$PATH:${LLVM_BUILD}
export LLVM_COMPILER=clang

export KERNEL=kernel8
pushd ../linux-pta
  export KCFLAGS="-march=armv8.5-a "
  BINUTILS_TARGET_PREFIX=aarch64-none-linux-gnu make \
      ARCH=arm64 CROSS_COMPILE=aarch64-none-linux-gnu- \
      HOSTCC=clang CC=wllvm -j5
  extract-bc -m vmlinux
  exit 0
  llvm-link -o vmlinux.bc `cat vmlinux.llvm.manifest`

popd
