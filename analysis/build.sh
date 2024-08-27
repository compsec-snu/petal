#!/bin/bash

PROJ_DIR=${PWD}/..


function build
{
    mkdir build
    pushd build
    cmake ../ \
        -DLLVM_DIR=${PROJ_DIR}/build/bin/llvm \
        -DLLVM_ROOT=${PROJ_DIR}/llvm-project \
        -DCMAKE_BUILD_TYPE=Debug \

    make -j4
    popd
}

build
