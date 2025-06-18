// REQUIRES: x86-registered-target,ld.lld

/// Simple test that DTLTO works with a single input bitcode file and that
/// --save-temps can be applied to the remote compilation.

// RUN: rm -rf %t && mkdir %t && cd %t

// RUN: %clang --target=x86_64-linux-gnu %s -shared -flto=thin \
// RUN:   -fthinlto-distributor=%python \
// RUN:   -Xthinlto-distributor=%llvm_src_root/utils/dtlto/local.py \
// RUN:   -Wl,--thinlto-remote-compiler-arg=--save-temps \
// RUN:   -fuse-ld=lld \
// RUN:   -nostdlib \
// RUN:   -Werror

/// Check that the required output files have been created.
// RUN: ls | count 9
// RUN: ls | FileCheck %s

/// Linked ELF.
// CHECK-DAG: {{^}}a.out{{$}}

/// --save-temps output for the backend compilation.
// CHECK-DAG: {{^}}dtlto-[[TMP:[a-zA-Z0-9_]+]].s{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.0.preopt.bc{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.1.promote.bc{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.2.internalize.bc{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.3.import.bc{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.4.opt.bc{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.5.precodegen.bc{{$}}
// CHECK-DAG: {{^}}dtlto-[[TMP]].s.resolution.txt{{$}}

int _start() { return 0; }
