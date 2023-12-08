//// Check driver handling for "-fvisibility-global-new-delete-hidden" and "-fvisibility-global-new-delete-normal".

//// -fvisibility-global-new-delete-hidden and -fvisibility-global-new-delete-hidden not added by default.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm %s 2>&1 | \
// RUN:   FileCheck -check-prefix=DEFAULTS %s --implicit-check-not=global-new-delete
// DEFAULTS-NOT: "-fvisibility-global-new-delete-normal"
// DEFAULTS-NOT: "-fvisibility-global-new-delete-hidden"

//// -fvisibility-global-new-delete-hidden added explicitly.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-hidden %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NDHIDDEN %s --implicit-check-not=global-new-delete
// NDHIDDEN-DAG: "-fvisibility-global-new-delete-hidden"

//// -fvisibility-global-new-delete-normal added explicitly.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-normal %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NDNORMAL %s --implicit-check-not=global-new-delete
// NDNORMAL-DAG: "-fvisibility-global-new-delete-normal"

//// -fvisibility-global-new-delete-normal disabled explicitly.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-normal -fno-visibility-global-new-delete-normal %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NO_NDNORMAL %s --implicit-check-not=global-new-delete
// NO_NDNORMAL-DAG: "-fno-visibility-global-new-delete-normal"

//// no error if both -fvisibility-global-new-delete-normal and -fno-visibility-global-new-delete-hidden specifed.
// RUN: %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-hidden -fno-visibility-global-new-delete-normal %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=NO_NDNORMAL,NDHIDDEN %s --implicit-check-not=global-new-delete

//// error if both -fvisibility-global-new-delete-normal and -fvisibility-global-new-delete-hidden specifed.
// RUN: not %clang -### -target x86_64-unknown-unknown -x cl -c -emit-llvm -fvisibility-global-new-delete-hidden -fno-visibility-global-new-delete-normal -fvisibility-global-new-delete-normal %s 2>&1 | \
// RUN:   FileCheck -check-prefixes=INCOMPAT %s
// INCOMPAT: clang: error: the combination of '-fvisibility-global-new-delete-normal' and '-fvisibility-global-new-delete-hidden' is incompatible
