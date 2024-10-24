## Test that --lto-cs-profile-file= can be specified.
## This is interesting as it requires an additional input file.

# RUN: rm -rf %t.dir && split-file %s %t.dir && cd %t.dir

## compile bitcode.
# RUN: echo "-triple x86_64-unknown-unknown -funified-lto -emit-llvm-bc -flto=thin" > c.rsp
# RUN: %clang_cc1 -x c foo.c -o foo.o @c.rsp
# RUN: %clang_cc1 -x c bar.c -o bar.o @c.rsp
# RUN: %clang_cc1 -x c _start.c -o _start.o @c.rsp

## Create an empty profile.
# RUN: touch empty.proftext
# RUN: llvm-profdata merge empty.proftext -o empty.profdata

# RUN: echo "foo.o bar.o _start.o \
# RUN:       --build-id=none \
# RUN:       --lto=thin --lto-O3 \
# RUN:       --thinlto-distributor=%python  \
# RUN:       -mllvm -thinlto-distributor-arg=%llvm_src_root/utils/dtlto/local.py \
# RUN:       --thinlto-remote-opt-tool=%clang" > l.rsp

## link passes with an empty profile.
# RUN: ld.lld @l.rsp --lto-cs-profile-file=empty.profdata

## Generate a broken profile to show that the profile
## is consumed by the backend compilations.
# RUN: echo "WOBBLER" > bad.profdata
# RUN: not ld.lld @l.rsp --lto-cs-profile-file=bad.profdata 2>&1 | FileCheck %s

# CHECK: Error in reading profile 
# CHECK: error: backend compilation error

#--- foo.c
void foo() {}

#--- bar.c
extern void foo();
void bar() {foo();}

#--- _start.c
extern void bar();
void _start() {bar();}
