#!/bin/bash -ve

# Build LLVM & passes
git clone https://github.com/llvm/llvm-project.git -b llvmorg-14.0.0 --depth=1
pushd llvm-project
  patch -p1 < ../scripts/petal-llvm-14.0.0.patch
popd


# Linux kernel 5.15.144
wget https://mirrors.edge.kernel.org/pub/linux/kernel/v5.x/linux-5.15.144.tar.gz
tar -xvf linux-5.15.144.tar.gz
mv linux-5.15.144 linux
pushd linux
  patch -p1 < ../scripts/petal-linux-5.15-qemu.patch
popd

cp linux linux-petal -r
cp linux linux-pta -r

cp scripts/config_ori linux/.config
cp scripts/config_petal linux-petal/.config
cp scripts/config_ori linux-pta/.config

pushd linux-pta
  patch -p1 < ../scripts/linux-pta.patch
popd

