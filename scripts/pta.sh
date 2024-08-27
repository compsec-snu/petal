#!/bin/bash -ve

BUILD=${PWD}/../build
PATH=${BUILD}/bin:${PATH}
args=("$@")

cp pta_log pta_log.old
cp crit.obj crit.obj.old
cp crit.ptr crit.ptr.old
cp crit.gobj crit.gobj.old
cp crit.gptr crit.gptr.old

# indcall
opt \
    -load=${PWD}/../analysis/build/src/libpetal.so \
    -enable-new-pm=0 \
    -indcall \
    -skiplist=skip.func \
    -skipvar=skip.var \
    -debug=1\
    -o indpta.bc \
    ${args[0]} 2>&1 | tee indcall_log
llvm-dis indpta.bc -o indpta.ll
cp func.code func.code.pta

opt \
    -load=${PWD}/../analysis/build/src/libpetal.so \
    -enable-new-pm=0 \
    -pta \
    -dump=pta.dump.priv \
    -skiplist=skip.func.pta \
    -funccode=func.code.pta \
    -debug=0 \
    -o pta-out.bc \
    indpta.bc > pta_log 2>&1
