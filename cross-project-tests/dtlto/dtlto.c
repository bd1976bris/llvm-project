// RUN: rm -rf %t && mkdir -p %t && cd %t

// RUN: %clang -target x86_64-linux-gnu %s -flto=thin \
// RUN:   -fthinlto-distributor=%python  \
// RUN:   -Xdist %llvm_src_root/utils/dtlto/local.py \
// RUN:   --save-temps \
// RUN:   -fuse-ld=lld \
// RUN:   -Wl,--save-temps \
// RUN:   -nostdlib \
// RUN:   -nostartfiles

/// Check that the required output files have been created.
// RUN: ls | tee %t.log | count 20
// RUN: ls | FileCheck %s --check-prefix=COMPILE
// RUN: ls | FileCheck %s --check-prefix=DTLTO
// RUN: ls | FileCheck %s --check-prefix=LTO

/// Files produced by the compiler.
// COMPILE: dtlto.bc
// COMPILE: dtlto.i
// COMPILE: dtlto.o

/// DTLTO native object output file for t.o.
// DTLTO: t{{.*}}.{{.*}}.native.o{{$}}
/// DTLTO imports file for t.o.
// DTLTO: {{.*}}.{{.*}}.native.o.imports{{$}}
/// DTLTO summary slice for t.o.
// DTLTO: t{{.*}}.{{.*}}.native.o.thinlto.bc{{$}}

// LTO: a.out{{$}}
/// save-temps incremental files for a.out
// LTO: a.out.0.0.preopt.bc{{$}}
// LTO: a.out.0.2.internalize.bc{{$}}
// LTO: a.out.dist-file.json{{$}}
// LTO: a.out.index.bc{{$}}
// LTO: a.out.index.dot{{$}}
// : a.out.lto.dtlto.o{{$}}
// LTO: a.out.resolution.txt{{$}}
/// save-temps incremental files for t.o.
// LTO: dtlto-{{.*}}.{{.*}}.native.o.0.preopt.bc{{$}}
// LTO: dtlto-{{.*}}.{{.*}}.native.o.1.promote.bc{{$}}
// LTO: dtlto-{{.*}}.{{.*}}.native.o.2.internalize.bc{{$}}
// LTO: dtlto-{{.*}}.{{.*}}.native.o.3.import.bc{{$}}
// LTO: dtlto-{{.*}}.{{.*}}.native.o.4.opt.bc{{$}}
// LTO: dtlto-{{.*}}.{{.*}}.native.o.5.precodegen.bc{{$}}
// LTO: dtlto-{{.*}}.{{.*}}.native.o.resolution.txt{{$}}

int _start() {return 0;}
