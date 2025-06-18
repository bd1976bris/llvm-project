# DTLTO
add_llvm_component_library(LLVMDTLTO
  Dtlto.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/ASMParser

  DEPENDS
  intrinsics_gen

  LINK_COMPONENTS
  Support
  )
