//// Check driver handling for "-fvisibility-global-new-delete-hidden" and "-fvisibility-global-new-delete-none".

//// -fvisibility-global-new-delete-hidden and -fvisibility-global-new-delete-hidden not added by default.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm %s 2>&1 | \
// RUN:   FileCheck -check-prefix=DEFAULTS %s --implicit-check-not=visibility-global-new-delete-hidden --implicit-check-not=visibility-global-new-delete-none
// DEFAULTS-NOT: "-fvisibility-global-new-delete-none"
// DEFAULTS-NOT: "-fvisibility-global-new-delete-hidden"

//// -fvisibility-global-new-delete-hidden added explicitly.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-hidden %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NDHIDDEN %s --implicit-check-not=visibility-global-new-delete-hidden --implicit-check-not=visibility-global-new-delete-none
// NDHIDDEN-DAG: "-fvisibility-global-new-delete-hidden"

//// -fvisibility-global-new-delete-none added explicitly.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-none %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NDNORMAL %s --implicit-check-not=visibility-global-new-delete-hidden --implicit-check-not=visibility-global-new-delete-none
// NDNORMAL-DAG: "-fvisibility-global-new-delete-none"

//// -fvisibility-global-new-delete-none disabled explicitly.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-none -fno-visibility-global-new-delete-none %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NO_NDNORMAL %s --implicit-check-not=visibility-global-new-delete-hidden --implicit-check-not=visibility-global-new-delete-none
// NO_NDNORMAL-DAG: "-fno-visibility-global-new-delete-none"

//// no error if both -fvisibility-global-new-delete-none and -fno-visibility-global-new-delete-hidden specifed.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-hidden -fno-visibility-global-new-delete-none %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NO_NDNORMAL,NDHIDDEN %s --implicit-check-not=visibility-global-new-delete-hidden --implicit-check-not=visibility-global-new-delete-none

//// error if both -fvisibility-global-new-delete-none and -fvisibility-global-new-delete-hidden specifed.
// RUN: not %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-hidden -fno-visibility-global-new-delete-none -fvisibility-global-new-delete-none %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=INCOMPAT %s
// INCOMPAT: clang: error: the combination of '-fvisibility-global-new-delete-none' and '-fvisibility-global-new-delete-hidden' is incompatible
