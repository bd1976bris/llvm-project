; Test that DTLTO writes the files it generates to the expected locations.

RUN: rm -rf %t && split-file %s %t && cd %t

# RUN: mkdir below && cd below

## Compile ThinLTO bitcode.
RUN: opt -thinlto-bc ../0.ll -o ../0.bc -O2
RUN: opt -thinlto-bc ../1.ll -o ../1.bc -O2

; Check that the expected set of filenames have been generated. Note that the
; use of validate.py will cause a failure as it does not create output files.
RUN: not llvm-lto2 run ../0.bc ../1.bc -o ../above.o \
RUN:   -dtlto-distributor=%python \
RUN:   -dtlto-distributor-arg=%llvm_src_root/utils/dtlto/validate.py \
RUN:   -r=../0.bc,g,px \
RUN:   -r=../1.bc,f,px \
RUN:   -r=../1.bc,g \
RUN:   -thinlto-emit-indexes -thinlto-emit-imports \
RUN: 2>&1 | FileCheck %s --check-prefixes=INPUTS,ERR

# INPUTS:      "jobs":

; Check the first job entry for 0.o. Note that 1.bc should not appear in the
; list of inputs for 0.o, as there are no imports from it.
INPUTS:      "args":
INPUTS-NEXT: "..{{(/|\\\\)}}0.bc"
INPUTS-NEXT: "-fthinlto-index=..{{(/|\\\\)}}0.1.[[#]].native.o.thinlto.bc"
INPUTS-NEXT: "-o"
INPUTS-NEXT: "..{{(/|\\\\)}}0.1.[[#]].native.o"
INPUTS-NEXT: ]
INPUTS:      "inputs": [
INPUTS-NEXT:   "..{{(/|\\\\)}}0.bc"
INPUTS-NEXT:   "..{{(/|\\\\)}}0.1.[[#]].native.o.thinlto.bc"
INPUTS-NEXT: ]
INPUTS:      "outputs": [
INPUTS-NEXT:   "..{{(/|\\\\)}}0.1.[[#]].native.o"
INPUTS-NEXT: ]

;  Check the second job entry for 1.o. Note that 0.o should appear in the list
; of inputs for 1.o, as there are imports from it.
INPUTS:      "args":
INPUTS-NEXT: "..{{(/|\\\\)}}1.bc"
INPUTS-NEXT: "-fthinlto-index=..{{(/|\\\\)}}1.2.[[#]].native.o.thinlto.bc"
INPUTS-NEXT: "-o"
INPUTS-NEXT: "..{{(/|\\\\)}}1.2.[[#]].native.o"
INPUTS-NEXT: ]
INPUTS:      "inputs": [
INPUTS-NEXT:   "..{{(/|\\\\)}}1.bc"
INPUTS-NEXT:   "..{{(/|\\\\)}}1.2.[[#]].native.o.thinlto.bc"
INPUTS-NEXT:   "..{{(/|\\\\)}}0.bc"
INPUTS-NEXT: ]
INPUTS:      "outputs": [
INPUTS-NEXT:   "..{{(/|\\\\)}}1.2.[[#]].native.o"
INPUTS-NEXT: ]

; This check ensures that we have failed for the expected reason.
ERR: failed: DTLTO backend compilation: cannot open native object file:

; Check that imports and index files were created as requested.
RUN: ls .. | FileCheck %s --check-prefix=FILES
FILES: 0.1.[[#]].native.o.thinlto.bc
FILES: 0.bc.imports
FILES: 1.2.[[#]].native.o.thinlto.bc
FILES: 1.bc.imports

;--- 0.ll
target datalayout = "e-m:e-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

define void @g() {
entry:
  ret void
}

;--- 1.ll
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

declare void @g(...)

define void @f() {
entry:
  call void (...) @g()
  ret void
}
