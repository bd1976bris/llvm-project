// RUN: %clang_cc1 %s -std=c++11 -triple x86_64-unknown-unknown -fvisibility-global-new-delete-none -emit-llvm -o - | FileCheck %s -DLINKAGE=dso_local
// RUN: %clang_cc1 %s -std=c++11 -triple x86_64-unknown-unknown -fvisibility=hidden -fvisibility-global-new-delete-none -emit-llvm -o - | FileCheck %s -DLINKAGE=hidden

//// Repeat tests but with an explict declaration present.
// RUN: %clang_cc1 %s -std=c++11 -triple x86_64-unknown-unknown -fvisibility-global-new-delete-none -emit-llvm -o - -DEXPLICIT_DECL | FileCheck %s -DLINKAGE=dso_local
// RUN: %clang_cc1 %s -std=c++11 -triple x86_64-unknown-unknown -fvisibility=hidden -fvisibility-global-new-delete-none -emit-llvm -o -  -DEXPLICIT_DECL | FileCheck %s -DLINKAGE=hidden

namespace std {
  typedef __typeof__(sizeof(0)) size_t;
  struct nothrow_t {};
}

// Definition which inherits visibility from the implicit compiler generated declaration.
#if defined(EXPLICIT_DECL)
void operator delete(void*) throw();
#endif
void operator delete(void*) throw() {}
// CHECK: define [[LINKAGE]]  void @_ZdlPv

// Definition which inherits visibility from the implicit compiler generated declaration,
#if defined(EXPLICIT_DECL)
void* operator new(std::size_t);
#endif
void* operator new(std::size_t) { return nullptr; }
// CHECK: define [[LINKAGE]]  noundef nonnull ptr @_Znwm

// Definition which does not have an implicit compiler generated declaration.
#if defined(EXPLICIT_DECL)
void* operator new(std::size_t, const std::nothrow_t&) noexcept;
#endif
void* operator new(std::size_t, const std::nothrow_t&) noexcept { return nullptr; }
// CHECK: define [[LINKAGE]]  noundef ptr @_ZnwmRKSt9nothrow_t
