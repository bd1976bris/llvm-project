// Check that an explicit visibility can be applied to the replaceable global new and delete operators.

// RUN: %clang_cc1 %s -std=c++11 -triple x86_64-unknown-unknown -fvisibility=hidden -fvisibility-global-new-delete-none -emit-llvm -o - | FileCheck %s
namespace std {
  typedef __typeof__(sizeof(0)) size_t;
  struct nothrow_t {};
}

__attribute__((visibility ("default")))
void operator delete(void*) throw();
void operator delete(void*) throw() {}
// CHECK: define dso_local void @_ZdlPv

#pragma GCC visibility push(default)

void* operator new(std::size_t);
void* operator new(std::size_t) { return nullptr; }
// CHECK: define dso_local noundef nonnull ptr @_Znwm

void* operator new(std::size_t, const std::nothrow_t&) throw();
void* operator new(std::size_t, const std::nothrow_t &) throw() { return nullptr; }
// CHECK: define dso_local noundef ptr @_ZnwmRKSt9nothrow_t

#pragma GCC visibility pop