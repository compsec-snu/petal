#!/bin/bash -e

BUILD_DIR=${PWD}/../build

build_clang_llvm() {
	if [ ! -d "$BUILD_DIR" ]; then
		mkdir ${BUILD_DIR}
	fi

	pushd ${BUILD_DIR}
	cmake -DLLVM_ENABLE_PROJECTS="clang;compiler-rt;lld" -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_DUMP=ON -G "Unix Makefiles" ../llvm-project/llvm
	make -j10
	popd
  export PATH=${BUILD_DIR}/bin:${PATH}
}

build_clang_llvm
