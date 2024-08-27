#!/bin/bash
export PATH=${PWD}/../build/bin:$PATH
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=../build/bin


build_analysis()
{
	export LLVM_ROOT=../llvm-project
    pushd ../analysis
    ./build.sh
    popd
}


build_analysis
