// Check that dllexport can be applied to the replaceable global new and delete operators.

// RUN: %clang_cc1 %s -std=c++11 -fdeclspec -triple x86_64-windows-itanium -fvisibility=hidden -fvisibility-global-new-delete-normal -emit-llvm -o - | FileCheck %s
namespace std {
  typedef __typeof__(sizeof(0)) size_t;
  struct nothrow_t {};
}

__declspec(dllexport) void operator delete(void*) throw();
void operator delete(void*) throw() {}
// CHECK: define dso_local dllexport void @_ZdlPv

__declspec(dllexport) void* operator new(std::size_t);
void* operator new(std::size_t) { return nullptr; }
// CHECK: define dso_local dllexport noundef nonnull ptr @_Znwy

__declspec(dllexport) void* operator new(std::size_t, const std::nothrow_t&) throw();
void* operator new(std::size_t, const std::nothrow_t &) throw() { return nullptr; }
// CHECK: define dso_local dllexport noundef ptr @_ZnwyRKSt9nothrow_t
