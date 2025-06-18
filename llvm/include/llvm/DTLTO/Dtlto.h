//===- Dtlto.h - Distributed ThinLTO functions and classes ----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_DTLTO_H
#define LLVM_DTLTO_H

#include "llvm/LTO/LTO.h"
#include "llvm/Support/MemoryBuffer.h"

namespace dtlto {

class ConfigTy;

llvm::Error run(llvm::lto::LTO &LtoObj);
} // namespace dtlto

#endif // LLVM_DTLTO_H
