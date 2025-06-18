// clang-format off
/// Test that -mllvm options are forwarded to the remote compiler for DTLTO.

// RUN: rm -rf %t && mkdir %t && cd %t

// RUN: %clang --target=x86_64-linux-gnu %s -shared -flto=thin \
// RUN:   -fthinlto-distributor=%python \
// RUN:   -Xthinlto-distributor=%llvm_src_root/utils/dtlto/local.py \
// RUN:   -fuse-ld=lld \
// RUN:   -nostdlib \
// RUN:   -Werror \
/// Specify -v for both the initial and remote clang invocations.
// RUN:   -v \
// RUN:   -Wl,--thinlto-remote-compiler-arg=-v \
// RUN:   -mllvm -print-after-all \
// RUN:   -mllvm=-print-before-all \
// RUN:   2>&1 | FileCheck %s

// -mllvm arguments are forwarded to `clang -cc1`.
// CHECK:       -mllvm -print-after-all
// CHECK-SAME:  -mllvm -print-before-all

// -mllvm arguments are forwarded to the remote compiler via lld.
// CHECK:       --thinlto-remote-compiler-arg=-mllvm=-print-after-all
// CHECK-SAME:  --thinlto-remote-compiler-arg=-mllvm=-print-before-all

// -mllvm arguments are forwarded to `clang -cc1` in the remote execution.
// CHECK:      -mllvm -print-after-all
// CHECK-SAME: -mllvm -print-before-all

int _start() { return 0; }
