# PeTAL

## Setup

```
# Download Clang/LLVM and the Linux kernel
./scripts/setup.sh

cd scripts

# Build LLVM
./build-llvm.sh

# Build libpetal.so
./build-analysis.sh

```

### Android kernel
Android kernel 5.10.136 for Galaxy S22 can be downloaded from
https://opensource.samsung.com/uploadList
(SM-S906B_13_Opensource.zip).


## Enforcing DFI

PeTAL first extracts a whole kernel bitcode file (`vmlinux.bc`) with
wllvm (from `./linux`) and then analyzes the kernel to enforce
two-level DFI. The analysis results are stored in a file named
`kdfi.dump`. 

A new kernel (in `./linux-petal`) is built with the DFI enforcement
using the analysis results. Before building the kernel, the file
paths in `KDFIInstrumentation.cpp` should be updated to the paths of
the scripts files in `./scripts`.

```
# Build a whole-kernel vmlinux.bc
./build-kernel-wllvm.sh 

# Analyze the kernel for PeTAL DFI analysis
./kdfi.sh ../linux/vmlinux.bc 

# Build the kernel with PeTAL DFI
./build-kernel-kdfi.sh

```

### Trouble shooting
If the `vmlinux.bc` is not generated, try excluding some bitcode
files (libstub) in `vmlinux.llvm.manifest` file and link the the
bitcode files in `vmlinux.llvm.manifest` by `llvm-link`.


## Finding access-control data (Privileged Type Analysis, PTA)

PTA identifies the error codes (eperm, eacces, erofs) by replacing
the error code with a named global constant. However, code using the
error codes in the left-hand side of a comparison will fail to
compile. Therefore, a python script (`build_pta.py`) is used to
automatically fix the code and rebuild the kernel. The script might
not be able to fix all the code, so manual intervention might be
required.


```
cd scripts

# Build a whole-kernel vmlinux.bc for PTA
python3 build_pta.py

# Run PTA
./pta.sh ../linux-pta/vmlinux.bc

```



