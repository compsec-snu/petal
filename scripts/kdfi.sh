#!/bin/bash -ve

BUILD=${PWD}/../build
PATH=${BUILD}/bin:${PATH}


cp kdfi_log kdfi_log.old
cp kdfi.dump kdfi.dump.old


args=("$@")

# indcall
opt -load=${PWD}/../analysis/build/src/libpetal.so \
    -enable-new-pm=0 \
    -indcall \
    -skiplist=skip.func \
    -skipvar=skip.var \
    -debug=0 \
    -o indout.bc \
    ${args[0]}
#opt -strip-debug indout.bc -o indout.bc
llvm-dis indout.bc -o indout.ll
cp func.code func.code.indout

#kdfi
opt \
    -load=${PWD}/../analysis/build/src/libpetal.so \
    -enable-new-pm=0 \
    -kdfi \
    -dump=kdfi.dump \
    -objlist=crit.obj \
    -ptrlist=crit.ptr \
    -gobjlist=crit.gobj \
    -gptrlist=crit.gptr \
    -skiplist=skip.func.kdfi \
    -funccode=func.code.indout \
    -debug=0 \
    -o kdfi-out.bc \
    indout.bc > kdfi_log 2>&1
