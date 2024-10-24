//===-LTO.cpp - LLVM Link Time Optimizer ----------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements functions and classes used to support LTO.
//
//===----------------------------------------------------------------------===//

#include "llvm/LTO/LTO.h"
#include "llvm/ADT/ScopeExit.h"
#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/StackSafetyAnalysis.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/Bitcode/BitcodeWriter.h"
#include "llvm/CodeGen/Analysis.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/AutoUpgrade.h"
#include "llvm/IR/DiagnosticPrinter.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMRemarkStreamer.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Mangler.h"
#include "llvm/IR/Metadata.h"
#include "llvm/LTO/LTOBackend.h"
#include "llvm/LTO/SummaryBasedOptimizations.h"
#include "llvm/Linker/IRMover.h"
#include "llvm/MC/TargetRegistry.h"
#include "llvm/Object/IRObjectFile.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/SHA1.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/ThreadPool.h"
#include "llvm/Support/Threading.h"
#include "llvm/Support/TimeProfiler.h"
#include "llvm/Support/ToolOutputFile.h"
#include "llvm/Support/VCSRevision.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Target/TargetOptions.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/IPO/MemProfContextDisambiguation.h"
#include "llvm/Transforms/IPO/WholeProgramDevirt.h"
#include "llvm/Transforms/Utils/FunctionImportUtils.h"
#include "llvm/Transforms/Utils/SplitModule.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/FileUtilities.h"
#include "llvm/Support/Process.h"

#include <optional>
#include <set>
#include <queue>
#include <sstream>

using namespace llvm;
using namespace lto;
using namespace object;

#define DEBUG_TYPE "lto"

static cl::opt<bool>
    DumpThinCGSCCs("dump-thin-cg-sccs", cl::init(false), cl::Hidden,
                   cl::desc("Dump the SCCs in the ThinLTO index's callgraph"));

namespace llvm {
/// Enable global value internalization in LTO.
cl::opt<bool> EnableLTOInternalization(
    "enable-lto-internalization", cl::init(true), cl::Hidden,
    cl::desc("Enable global value internalization in LTO"));

/// Indicate we are linking with an allocator that supports hot/cold operator
/// new interfaces.
extern cl::opt<bool> SupportsHotColdNew;

/// Enable MemProf context disambiguation for thin link.
extern cl::opt<bool> EnableMemProfContextDisambiguation;

/// --thinlto-distributor-arg
cl::list<std::string> AdditionalThinLTODistributorArgs(
    "thinlto-distributor-arg", cl::desc("Additional arguments to pass to the thinlto distributor"));

/// --thinlto-distributor-arg
cl::list<std::string> AdditionalThinLTODCC1Args(
    "thinlto-cc1-arg",
    cl::desc("Additional arguments to pass to the thinlto remote opt tool"));
} // namespace llvm

// Computes a unique hash for the Module considering the current list of
// export/import and other global analysis results.
// The hash is produced in \p Key.
void llvm::computeLTOCacheKey(
    SmallString<40> &Key, const Config &Conf, const ModuleSummaryIndex &Index,
    StringRef ModuleID, const FunctionImporter::ImportMapTy &ImportList,
    const FunctionImporter::ExportSetTy &ExportList,
    const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
    const GVSummaryMapTy &DefinedGlobals,
    const std::set<GlobalValue::GUID> &CfiFunctionDefs,
    const std::set<GlobalValue::GUID> &CfiFunctionDecls,
    std::optional<unsigned> salt) {
  // Compute the unique hash for this entry.
  // This is based on the current compiler version, the module itself, the
  // export list, the hash for every single module in the import list, the
  // list of ResolvedODR for the module, and the list of preserved symbols.
  SHA1 Hasher;

  // Start with the compiler revision
  Hasher.update(LLVM_VERSION_STRING);
#ifdef LLVM_REVISION
  Hasher.update(LLVM_REVISION);
#endif

  // Include the parts of the LTO configuration that affect code generation.
  auto AddString = [&](StringRef Str) {
    Hasher.update(Str);
    Hasher.update(ArrayRef<uint8_t>{0});
  };
  auto AddUnsigned = [&](unsigned I) {
    uint8_t Data[4];
    support::endian::write32le(Data, I);
    Hasher.update(Data);
  };
  auto AddUint64 = [&](uint64_t I) {
    uint8_t Data[8];
    support::endian::write64le(Data, I);
    Hasher.update(Data);
  };
  auto AddUint8 = [&](const uint8_t I) {
    Hasher.update(ArrayRef<uint8_t>((const uint8_t *)&I, 1));
  };
  AddString(Conf.CPU);
  // FIXME: Hash more of Options. For now all clients initialize Options from
  // command-line flags (which is unsupported in production), but may set
  // X86RelaxRelocations. The clang driver can also pass FunctionSections,
  // DataSections and DebuggerTuning via command line flags.
  AddUnsigned(Conf.Options.MCOptions.X86RelaxRelocations);
  AddUnsigned(Conf.Options.FunctionSections);
  AddUnsigned(Conf.Options.DataSections);
  AddUnsigned((unsigned)Conf.Options.DebuggerTuning);
  for (auto &A : Conf.MAttrs)
    AddString(A);
  if (Conf.RelocModel)
    AddUnsigned(*Conf.RelocModel);
  else
    AddUnsigned(-1);
  if (Conf.CodeModel)
    AddUnsigned(*Conf.CodeModel);
  else
    AddUnsigned(-1);
  for (const auto &S : Conf.MllvmArgs)
    AddString(S);
  AddUnsigned(static_cast<int>(Conf.CGOptLevel));
  AddUnsigned(static_cast<int>(Conf.CGFileType));
  AddUnsigned(Conf.OptLevel);
  AddUnsigned(Conf.Freestanding);
  AddString(Conf.OptPipeline);
  AddString(Conf.AAPipeline);
  AddString(Conf.OverrideTriple);
  AddString(Conf.DefaultTriple);
  AddString(Conf.DwoDir);

  // Hash an integer to distinguish ThinLTO from DTLTO cache entries because
  // the user might choose one directory for both of them. Cache entry names
  // collisions between ThinLTO and DTLTO might cause miscompile.
  if (salt)
    AddUnsigned(*salt);

  // Include the hash for the current module
  auto ModHash = Index.getModuleHash(ModuleID);
  Hasher.update(ArrayRef<uint8_t>((uint8_t *)&ModHash[0], sizeof(ModHash)));

  std::vector<uint64_t> ExportsGUID;
  ExportsGUID.reserve(ExportList.size());
  for (const auto &VI : ExportList) {
    auto GUID = VI.getGUID();
    ExportsGUID.push_back(GUID);
  }

  // Sort the export list elements GUIDs.
  llvm::sort(ExportsGUID);
  for (uint64_t GUID : ExportsGUID) {
    // The export list can impact the internalization, be conservative here
    Hasher.update(ArrayRef<uint8_t>((uint8_t *)&GUID, sizeof(GUID)));
  }

  // Include the hash for every module we import functions from. The set of
  // imported symbols for each module may affect code generation and is
  // sensitive to link order, so include that as well.
  using ImportMapIteratorTy = FunctionImporter::ImportMapTy::const_iterator;
  struct ImportModule {
    ImportMapIteratorTy ModIt;
    const ModuleSummaryIndex::ModuleInfo *ModInfo;

    StringRef getIdentifier() const { return ModIt->getFirst(); }
    const FunctionImporter::FunctionsToImportTy &getFunctions() const {
      return ModIt->second;
    }

    const ModuleHash &getHash() const { return ModInfo->second; }
  };

  std::vector<ImportModule> ImportModulesVector;
  ImportModulesVector.reserve(ImportList.size());

  for (ImportMapIteratorTy It = ImportList.begin(); It != ImportList.end();
       ++It) {
    ImportModulesVector.push_back({It, Index.getModule(It->getFirst())});
  }
  // Order using module hash, to be both independent of module name and
  // module order.
  llvm::sort(ImportModulesVector,
             [](const ImportModule &Lhs, const ImportModule &Rhs) -> bool {
               return Lhs.getHash() < Rhs.getHash();
             });
  std::vector<uint64_t> ImportedGUIDs;
  for (const ImportModule &Entry : ImportModulesVector) {
    auto ModHash = Entry.getHash();
    Hasher.update(ArrayRef<uint8_t>((uint8_t *)&ModHash[0], sizeof(ModHash)));

    AddUint64(Entry.getFunctions().size());

    ImportedGUIDs.clear();
    for (auto &Fn : Entry.getFunctions())
      ImportedGUIDs.push_back(Fn);
    llvm::sort(ImportedGUIDs);
    for (auto &GUID : ImportedGUIDs)
      AddUint64(GUID);
  }

  // Include the hash for the resolved ODR.
  for (auto &Entry : ResolvedODR) {
    Hasher.update(ArrayRef<uint8_t>((const uint8_t *)&Entry.first,
                                    sizeof(GlobalValue::GUID)));
    Hasher.update(ArrayRef<uint8_t>((const uint8_t *)&Entry.second,
                                    sizeof(GlobalValue::LinkageTypes)));
  }

  // Members of CfiFunctionDefs and CfiFunctionDecls that are referenced or
  // defined in this module.
  std::set<GlobalValue::GUID> UsedCfiDefs;
  std::set<GlobalValue::GUID> UsedCfiDecls;

  // Typeids used in this module.
  std::set<GlobalValue::GUID> UsedTypeIds;

  auto AddUsedCfiGlobal = [&](GlobalValue::GUID ValueGUID) {
    if (CfiFunctionDefs.count(ValueGUID))
      UsedCfiDefs.insert(ValueGUID);
    if (CfiFunctionDecls.count(ValueGUID))
      UsedCfiDecls.insert(ValueGUID);
  };

  auto AddUsedThings = [&](GlobalValueSummary *GS) {
    if (!GS) return;
    AddUnsigned(GS->getVisibility());
    AddUnsigned(GS->isLive());
    AddUnsigned(GS->canAutoHide());
    for (const ValueInfo &VI : GS->refs()) {
      AddUnsigned(VI.isDSOLocal(Index.withDSOLocalPropagation()));
      AddUsedCfiGlobal(VI.getGUID());
    }
    if (auto *GVS = dyn_cast<GlobalVarSummary>(GS)) {
      AddUnsigned(GVS->maybeReadOnly());
      AddUnsigned(GVS->maybeWriteOnly());
    }
    if (auto *FS = dyn_cast<FunctionSummary>(GS)) {
      for (auto &TT : FS->type_tests())
        UsedTypeIds.insert(TT);
      for (auto &TT : FS->type_test_assume_vcalls())
        UsedTypeIds.insert(TT.GUID);
      for (auto &TT : FS->type_checked_load_vcalls())
        UsedTypeIds.insert(TT.GUID);
      for (auto &TT : FS->type_test_assume_const_vcalls())
        UsedTypeIds.insert(TT.VFunc.GUID);
      for (auto &TT : FS->type_checked_load_const_vcalls())
        UsedTypeIds.insert(TT.VFunc.GUID);
      for (auto &ET : FS->calls()) {
        AddUnsigned(ET.first.isDSOLocal(Index.withDSOLocalPropagation()));
        AddUsedCfiGlobal(ET.first.getGUID());
      }
    }
  };

  // Include the hash for the linkage type to reflect internalization and weak
  // resolution, and collect any used type identifier resolutions.
  for (auto &GS : DefinedGlobals) {
    GlobalValue::LinkageTypes Linkage = GS.second->linkage();
    Hasher.update(
        ArrayRef<uint8_t>((const uint8_t *)&Linkage, sizeof(Linkage)));
    AddUsedCfiGlobal(GS.first);
    AddUsedThings(GS.second);
  }

  // Imported functions may introduce new uses of type identifier resolutions,
  // so we need to collect their used resolutions as well.
  for (const ImportModule &ImpM : ImportModulesVector)
    for (auto &ImpF : ImpM.getFunctions()) {
      GlobalValueSummary *S =
          Index.findSummaryInModule(ImpF, ImpM.getIdentifier());
      AddUsedThings(S);
      // If this is an alias, we also care about any types/etc. that the aliasee
      // may reference.
      if (auto *AS = dyn_cast_or_null<AliasSummary>(S))
        AddUsedThings(AS->getBaseObject());
    }

  auto AddTypeIdSummary = [&](StringRef TId, const TypeIdSummary &S) {
    AddString(TId);

    AddUnsigned(S.TTRes.TheKind);
    AddUnsigned(S.TTRes.SizeM1BitWidth);

    AddUint64(S.TTRes.AlignLog2);
    AddUint64(S.TTRes.SizeM1);
    AddUint64(S.TTRes.BitMask);
    AddUint64(S.TTRes.InlineBits);

    AddUint64(S.WPDRes.size());
    for (auto &WPD : S.WPDRes) {
      AddUnsigned(WPD.first);
      AddUnsigned(WPD.second.TheKind);
      AddString(WPD.second.SingleImplName);

      AddUint64(WPD.second.ResByArg.size());
      for (auto &ByArg : WPD.second.ResByArg) {
        AddUint64(ByArg.first.size());
        for (uint64_t Arg : ByArg.first)
          AddUint64(Arg);
        AddUnsigned(ByArg.second.TheKind);
        AddUint64(ByArg.second.Info);
        AddUnsigned(ByArg.second.Byte);
        AddUnsigned(ByArg.second.Bit);
      }
    }
  };

  // Include the hash for all type identifiers used by this module.
  for (GlobalValue::GUID TId : UsedTypeIds) {
    auto TidIter = Index.typeIds().equal_range(TId);
    for (auto It = TidIter.first; It != TidIter.second; ++It)
      AddTypeIdSummary(It->second.first, It->second.second);
  }

  AddUnsigned(UsedCfiDefs.size());
  for (auto &V : UsedCfiDefs)
    AddUint64(V);

  AddUnsigned(UsedCfiDecls.size());
  for (auto &V : UsedCfiDecls)
    AddUint64(V);

  if (!Conf.SampleProfile.empty()) {
    auto FileOrErr = MemoryBuffer::getFile(Conf.SampleProfile);
    if (FileOrErr) {
      Hasher.update(FileOrErr.get()->getBuffer());

      if (!Conf.ProfileRemapping.empty()) {
        FileOrErr = MemoryBuffer::getFile(Conf.ProfileRemapping);
        if (FileOrErr)
          Hasher.update(FileOrErr.get()->getBuffer());
      }
    }
  }

  Key = toHex(Hasher.result());
}

static void thinLTOResolvePrevailingGUID(
    const Config &C, ValueInfo VI,
    DenseSet<GlobalValueSummary *> &GlobalInvolvedWithAlias,
    function_ref<bool(GlobalValue::GUID, const GlobalValueSummary *)>
        isPrevailing,
    function_ref<void(StringRef, GlobalValue::GUID, GlobalValue::LinkageTypes)>
        recordNewLinkage,
    const DenseSet<GlobalValue::GUID> &GUIDPreservedSymbols) {
  GlobalValue::VisibilityTypes Visibility =
      C.VisibilityScheme == Config::ELF ? VI.getELFVisibility()
                                        : GlobalValue::DefaultVisibility;
  for (auto &S : VI.getSummaryList()) {
    GlobalValue::LinkageTypes OriginalLinkage = S->linkage();
    // Ignore local and appending linkage values since the linker
    // doesn't resolve them.
    if (GlobalValue::isLocalLinkage(OriginalLinkage) ||
        GlobalValue::isAppendingLinkage(S->linkage()))
      continue;
    // We need to emit only one of these. The prevailing module will keep it,
    // but turned into a weak, while the others will drop it when possible.
    // This is both a compile-time optimization and a correctness
    // transformation. This is necessary for correctness when we have exported
    // a reference - we need to convert the linkonce to weak to
    // ensure a copy is kept to satisfy the exported reference.
    // FIXME: We may want to split the compile time and correctness
    // aspects into separate routines.
    if (isPrevailing(VI.getGUID(), S.get())) {
      if (GlobalValue::isLinkOnceLinkage(OriginalLinkage)) {
        S->setLinkage(GlobalValue::getWeakLinkage(
            GlobalValue::isLinkOnceODRLinkage(OriginalLinkage)));
        // The kept copy is eligible for auto-hiding (hidden visibility) if all
        // copies were (i.e. they were all linkonce_odr global unnamed addr).
        // If any copy is not (e.g. it was originally weak_odr), then the symbol
        // must remain externally available (e.g. a weak_odr from an explicitly
        // instantiated template). Additionally, if it is in the
        // GUIDPreservedSymbols set, that means that it is visibile outside
        // the summary (e.g. in a native object or a bitcode file without
        // summary), and in that case we cannot hide it as it isn't possible to
        // check all copies.
        S->setCanAutoHide(VI.canAutoHide() &&
                          !GUIDPreservedSymbols.count(VI.getGUID()));
      }
      if (C.VisibilityScheme == Config::FromPrevailing)
        Visibility = S->getVisibility();
    }
    // Alias and aliasee can't be turned into available_externally.
    else if (!isa<AliasSummary>(S.get()) &&
             !GlobalInvolvedWithAlias.count(S.get()))
      S->setLinkage(GlobalValue::AvailableExternallyLinkage);

    // For ELF, set visibility to the computed visibility from summaries. We
    // don't track visibility from declarations so this may be more relaxed than
    // the most constraining one.
    if (C.VisibilityScheme == Config::ELF)
      S->setVisibility(Visibility);

    if (S->linkage() != OriginalLinkage)
      recordNewLinkage(S->modulePath(), VI.getGUID(), S->linkage());
  }

  if (C.VisibilityScheme == Config::FromPrevailing) {
    for (auto &S : VI.getSummaryList()) {
      GlobalValue::LinkageTypes OriginalLinkage = S->linkage();
      if (GlobalValue::isLocalLinkage(OriginalLinkage) ||
          GlobalValue::isAppendingLinkage(S->linkage()))
        continue;
      S->setVisibility(Visibility);
    }
  }
}

/// Resolve linkage for prevailing symbols in the \p Index.
//
// We'd like to drop these functions if they are no longer referenced in the
// current module. However there is a chance that another module is still
// referencing them because of the import. We make sure we always emit at least
// one copy.
void llvm::thinLTOResolvePrevailingInIndex(
    const Config &C, ModuleSummaryIndex &Index,
    function_ref<bool(GlobalValue::GUID, const GlobalValueSummary *)>
        isPrevailing,
    function_ref<void(StringRef, GlobalValue::GUID, GlobalValue::LinkageTypes)>
        recordNewLinkage,
    const DenseSet<GlobalValue::GUID> &GUIDPreservedSymbols) {
  // We won't optimize the globals that are referenced by an alias for now
  // Ideally we should turn the alias into a global and duplicate the definition
  // when needed.
  DenseSet<GlobalValueSummary *> GlobalInvolvedWithAlias;
  for (auto &I : Index)
    for (auto &S : I.second.SummaryList)
      if (auto AS = dyn_cast<AliasSummary>(S.get()))
        GlobalInvolvedWithAlias.insert(&AS->getAliasee());

  for (auto &I : Index)
    thinLTOResolvePrevailingGUID(C, Index.getValueInfo(I),
                                 GlobalInvolvedWithAlias, isPrevailing,
                                 recordNewLinkage, GUIDPreservedSymbols);
}

static void thinLTOInternalizeAndPromoteGUID(
    ValueInfo VI, function_ref<bool(StringRef, ValueInfo)> isExported,
    function_ref<bool(GlobalValue::GUID, const GlobalValueSummary *)>
        isPrevailing) {
  auto ExternallyVisibleCopies =
      llvm::count_if(VI.getSummaryList(),
                     [](const std::unique_ptr<GlobalValueSummary> &Summary) {
                       return !GlobalValue::isLocalLinkage(Summary->linkage());
                     });

  for (auto &S : VI.getSummaryList()) {
    // First see if we need to promote an internal value because it is not
    // exported.
    if (isExported(S->modulePath(), VI)) {
      if (GlobalValue::isLocalLinkage(S->linkage()))
        S->setLinkage(GlobalValue::ExternalLinkage);
      continue;
    }

    // Otherwise, see if we can internalize.
    if (!EnableLTOInternalization)
      continue;

    // Non-exported values with external linkage can be internalized.
    if (GlobalValue::isExternalLinkage(S->linkage())) {
      S->setLinkage(GlobalValue::InternalLinkage);
      continue;
    }

    // Non-exported function and variable definitions with a weak-for-linker
    // linkage can be internalized in certain cases. The minimum legality
    // requirements would be that they are not address taken to ensure that we
    // don't break pointer equality checks, and that variables are either read-
    // or write-only. For functions, this is the case if either all copies are
    // [local_]unnamed_addr, or we can propagate reference edge attributes
    // (which is how this is guaranteed for variables, when analyzing whether
    // they are read or write-only).
    //
    // However, we only get to this code for weak-for-linkage values in one of
    // two cases:
    // 1) The prevailing copy is not in IR (it is in native code).
    // 2) The prevailing copy in IR is not exported from its module.
    // Additionally, at least for the new LTO API, case 2 will only happen if
    // there is exactly one definition of the value (i.e. in exactly one
    // module), as duplicate defs are result in the value being marked exported.
    // Likely, users of the legacy LTO API are similar, however, currently there
    // are llvm-lto based tests of the legacy LTO API that do not mark
    // duplicate linkonce_odr copies as exported via the tool, so we need
    // to handle that case below by checking the number of copies.
    //
    // Generally, we only want to internalize a weak-for-linker value in case
    // 2, because in case 1 we cannot see how the value is used to know if it
    // is read or write-only. We also don't want to bloat the binary with
    // multiple internalized copies of non-prevailing linkonce/weak functions.
    // Note if we don't internalize, we will convert non-prevailing copies to
    // available_externally anyway, so that we drop them after inlining. The
    // only reason to internalize such a function is if we indeed have a single
    // copy, because internalizing it won't increase binary size, and enables
    // use of inliner heuristics that are more aggressive in the face of a
    // single call to a static (local). For variables, internalizing a read or
    // write only variable can enable more aggressive optimization. However, we
    // already perform this elsewhere in the ThinLTO backend handling for
    // read or write-only variables (processGlobalForThinLTO).
    //
    // Therefore, only internalize linkonce/weak if there is a single copy, that
    // is prevailing in this IR module. We can do so aggressively, without
    // requiring the address to be insignificant, or that a variable be read or
    // write-only.
    if (!GlobalValue::isWeakForLinker(S->linkage()) ||
        GlobalValue::isExternalWeakLinkage(S->linkage()))
      continue;

    if (isPrevailing(VI.getGUID(), S.get()) && ExternallyVisibleCopies == 1)
      S->setLinkage(GlobalValue::InternalLinkage);
  }
}

// Update the linkages in the given \p Index to mark exported values
// as external and non-exported values as internal.
void llvm::thinLTOInternalizeAndPromoteInIndex(
    ModuleSummaryIndex &Index,
    function_ref<bool(StringRef, ValueInfo)> isExported,
    function_ref<bool(GlobalValue::GUID, const GlobalValueSummary *)>
        isPrevailing) {
  for (auto &I : Index)
    thinLTOInternalizeAndPromoteGUID(Index.getValueInfo(I), isExported,
                                     isPrevailing);
}

// Requires a destructor for std::vector<InputModule>.
InputFile::~InputFile() = default;

Expected<std::unique_ptr<InputFile>> InputFile::create(MemoryBufferRef Object) {
  std::unique_ptr<InputFile> File(new InputFile);

  Expected<IRSymtabFile> FOrErr = readIRSymtab(Object);
  if (!FOrErr)
    return FOrErr.takeError();

  File->TargetTriple = FOrErr->TheReader.getTargetTriple();
  File->SourceFileName = FOrErr->TheReader.getSourceFileName();
  File->COFFLinkerOpts = FOrErr->TheReader.getCOFFLinkerOpts();
  File->DependentLibraries = FOrErr->TheReader.getDependentLibraries();
  File->ComdatTable = FOrErr->TheReader.getComdatTable();

  for (unsigned I = 0; I != FOrErr->Mods.size(); ++I) {
    size_t Begin = File->Symbols.size();
    for (const irsymtab::Reader::SymbolRef &Sym :
         FOrErr->TheReader.module_symbols(I))
      // Skip symbols that are irrelevant to LTO. Note that this condition needs
      // to match the one in Skip() in LTO::addRegularLTO().
      if (Sym.isGlobal() && !Sym.isFormatSpecific())
        File->Symbols.push_back(Sym);
    File->ModuleSymIndices.push_back({Begin, File->Symbols.size()});
  }

  File->Mods = FOrErr->Mods;
  File->Strtab = std::move(FOrErr->Strtab);
  return std::move(File);
}

StringRef InputFile::getName() const {
  return Mods[0].getModuleIdentifier();
}

BitcodeModule &InputFile::getSingleBitcodeModule() {
  assert(Mods.size() == 1 && "Expect only one bitcode module");
  return Mods[0];
}

LTO::RegularLTOState::RegularLTOState(unsigned ParallelCodeGenParallelismLevel,
                                      const Config &Conf)
    : ParallelCodeGenParallelismLevel(ParallelCodeGenParallelismLevel),
      Ctx(Conf), CombinedModule(std::make_unique<Module>("ld-temp.o", Ctx)),
      Mover(std::make_unique<IRMover>(*CombinedModule)) {
  CombinedModule->IsNewDbgInfoFormat = UseNewDbgInfoFormat;
}

LTO::ThinLTOState::ThinLTOState(ThinBackend Backend)
    : Backend(Backend), CombinedIndex(/*HaveGVs*/ false) {
  if (!Backend)
    this->Backend =
        createInProcessThinBackend(llvm::heavyweight_hardware_concurrency());
}

LTO::LTO(Config Conf, ThinBackend Backend,
         unsigned ParallelCodeGenParallelismLevel, LTOKind LTOMode)
    : Conf(std::move(Conf)),
      RegularLTO(ParallelCodeGenParallelismLevel, this->Conf),
      ThinLTO(std::move(Backend)),
      GlobalResolutions(std::make_optional<StringMap<GlobalResolution>>()),
      LTOMode(LTOMode) {}

// Requires a destructor for MapVector<BitcodeModule>.
LTO::~LTO() = default;

// Add the symbols in the given module to the GlobalResolutions map, and resolve
// their partitions.
void LTO::addModuleToGlobalRes(ArrayRef<InputFile::Symbol> Syms,
                               ArrayRef<SymbolResolution> Res,
                               unsigned Partition, bool InSummary) {
  auto *ResI = Res.begin();
  auto *ResE = Res.end();
  (void)ResE;
  const Triple TT(RegularLTO.CombinedModule->getTargetTriple());
  for (const InputFile::Symbol &Sym : Syms) {
    assert(ResI != ResE);
    SymbolResolution Res = *ResI++;

    auto &GlobalRes = (*GlobalResolutions)[Sym.getName()];
    GlobalRes.UnnamedAddr &= Sym.isUnnamedAddr();
    if (Res.Prevailing) {
      assert(!GlobalRes.Prevailing &&
             "Multiple prevailing defs are not allowed");
      GlobalRes.Prevailing = true;
      GlobalRes.IRName = std::string(Sym.getIRName());
    } else if (!GlobalRes.Prevailing && GlobalRes.IRName.empty()) {
      // Sometimes it can be two copies of symbol in a module and prevailing
      // symbol can have no IR name. That might happen if symbol is defined in
      // module level inline asm block. In case we have multiple modules with
      // the same symbol we want to use IR name of the prevailing symbol.
      // Otherwise, if we haven't seen a prevailing symbol, set the name so that
      // we can later use it to check if there is any prevailing copy in IR.
      GlobalRes.IRName = std::string(Sym.getIRName());
    }

    // In rare occasion, the symbol used to initialize GlobalRes has a different
    // IRName from the inspected Symbol. This can happen on macOS + iOS, when a
    // symbol is referenced through its mangled name, say @"\01_symbol" while
    // the IRName is @symbol (the prefix underscore comes from MachO mangling).
    // In that case, we have the same actual Symbol that can get two different
    // GUID, leading to some invalid internalization. Workaround this by marking
    // the GlobalRes external.

    // FIXME: instead of this check, it would be desirable to compute GUIDs
    // based on mangled name, but this requires an access to the Target Triple
    // and would be relatively invasive on the codebase.
    if (GlobalRes.IRName != Sym.getIRName()) {
      GlobalRes.Partition = GlobalResolution::External;
      GlobalRes.VisibleOutsideSummary = true;
    }

    // Set the partition to external if we know it is re-defined by the linker
    // with -defsym or -wrap options, used elsewhere, e.g. it is visible to a
    // regular object, is referenced from llvm.compiler.used/llvm.used, or was
    // already recorded as being referenced from a different partition.
    if (Res.LinkerRedefined || Res.VisibleToRegularObj || Sym.isUsed() ||
        (GlobalRes.Partition != GlobalResolution::Unknown &&
         GlobalRes.Partition != Partition)) {
      GlobalRes.Partition = GlobalResolution::External;
    } else
      // First recorded reference, save the current partition.
      GlobalRes.Partition = Partition;

    // Flag as visible outside of summary if visible from a regular object or
    // from a module that does not have a summary.
    GlobalRes.VisibleOutsideSummary |=
        (Res.VisibleToRegularObj || Sym.isUsed() || !InSummary);

    GlobalRes.ExportDynamic |= Res.ExportDynamic;
  }
}

static void writeToResolutionFile(raw_ostream &OS, InputFile *Input,
                                  ArrayRef<SymbolResolution> Res) {
  StringRef Path = Input->getName();
  OS << Path << '\n';
  auto ResI = Res.begin();
  for (const InputFile::Symbol &Sym : Input->symbols()) {
    assert(ResI != Res.end());
    SymbolResolution Res = *ResI++;

    OS << "-r=" << Path << ',' << Sym.getName() << ',';
    if (Res.Prevailing)
      OS << 'p';
    if (Res.FinalDefinitionInLinkageUnit)
      OS << 'l';
    if (Res.VisibleToRegularObj)
      OS << 'x';
    if (Res.LinkerRedefined)
      OS << 'r';
    OS << '\n';
  }
  OS.flush();
  assert(ResI == Res.end());
}

Error LTO::add(std::unique_ptr<InputFile> Input,
               ArrayRef<SymbolResolution> Res) {
  assert(!CalledGetMaxTasks);

  if (Conf.ResolutionFile)
    writeToResolutionFile(*Conf.ResolutionFile, Input.get(), Res);

  if (RegularLTO.CombinedModule->getTargetTriple().empty()) {
    RegularLTO.CombinedModule->setTargetTriple(Input->getTargetTriple());
    if (Triple(Input->getTargetTriple()).isOSBinFormatELF())
      Conf.VisibilityScheme = Config::ELF;
  }

  const SymbolResolution *ResI = Res.begin();
  for (unsigned I = 0; I != Input->Mods.size(); ++I)
    if (Error Err = addModule(*Input, I, ResI, Res.end()))
      return Err;

  assert(ResI == Res.end());
  return Error::success();
}

Error LTO::addModule(InputFile &Input, unsigned ModI,
                     const SymbolResolution *&ResI,
                     const SymbolResolution *ResE) {
  Expected<BitcodeLTOInfo> LTOInfo = Input.Mods[ModI].getLTOInfo();
  if (!LTOInfo)
    return LTOInfo.takeError();

  if (EnableSplitLTOUnit) {
    // If only some modules were split, flag this in the index so that
    // we can skip or error on optimizations that need consistently split
    // modules (whole program devirt and lower type tests).
    if (*EnableSplitLTOUnit != LTOInfo->EnableSplitLTOUnit)
      ThinLTO.CombinedIndex.setPartiallySplitLTOUnits();
  } else
    EnableSplitLTOUnit = LTOInfo->EnableSplitLTOUnit;

  BitcodeModule BM = Input.Mods[ModI];

  if ((LTOMode == LTOK_UnifiedRegular || LTOMode == LTOK_UnifiedThin) &&
      !LTOInfo->UnifiedLTO)
    return make_error<StringError>(
        "unified LTO compilation must use "
        "compatible bitcode modules (use -funified-lto)",
        inconvertibleErrorCode());

  if (LTOInfo->UnifiedLTO && LTOMode == LTOK_Default)
    LTOMode = LTOK_UnifiedThin;

  bool IsThinLTO = LTOInfo->IsThinLTO && (LTOMode != LTOK_UnifiedRegular);

  auto ModSyms = Input.module_symbols(ModI);
  addModuleToGlobalRes(ModSyms, {ResI, ResE},
                       IsThinLTO ? ThinLTO.ModuleMap.size() + 1 : 0,
                       LTOInfo->HasSummary);

  if (IsThinLTO)
    return addThinLTO(BM, ModSyms, ResI, ResE);

  RegularLTO.EmptyCombinedModule = false;
  Expected<RegularLTOState::AddedModule> ModOrErr =
      addRegularLTO(BM, ModSyms, ResI, ResE);
  if (!ModOrErr)
    return ModOrErr.takeError();

  if (!LTOInfo->HasSummary)
    return linkRegularLTO(std::move(*ModOrErr), /*LivenessFromIndex=*/false);

  // Regular LTO module summaries are added to a dummy module that represents
  // the combined regular LTO module.
  if (Error Err = BM.readSummary(ThinLTO.CombinedIndex, ""))
    return Err;
  RegularLTO.ModsWithSummaries.push_back(std::move(*ModOrErr));
  return Error::success();
}

// Checks whether the given global value is in a non-prevailing comdat
// (comdat containing values the linker indicated were not prevailing,
// which we then dropped to available_externally), and if so, removes
// it from the comdat. This is called for all global values to ensure the
// comdat is empty rather than leaving an incomplete comdat. It is needed for
// regular LTO modules, in case we are in a mixed-LTO mode (both regular
// and thin LTO modules) compilation. Since the regular LTO module will be
// linked first in the final native link, we want to make sure the linker
// doesn't select any of these incomplete comdats that would be left
// in the regular LTO module without this cleanup.
static void
handleNonPrevailingComdat(GlobalValue &GV,
                          std::set<const Comdat *> &NonPrevailingComdats) {
  Comdat *C = GV.getComdat();
  if (!C)
    return;

  if (!NonPrevailingComdats.count(C))
    return;

  // Additionally need to drop all global values from the comdat to
  // available_externally, to satisfy the COMDAT requirement that all members
  // are discarded as a unit. The non-local linkage global values avoid
  // duplicate definition linker errors.
  GV.setLinkage(GlobalValue::AvailableExternallyLinkage);

  if (auto GO = dyn_cast<GlobalObject>(&GV))
    GO->setComdat(nullptr);
}

// Add a regular LTO object to the link.
// The resulting module needs to be linked into the combined LTO module with
// linkRegularLTO.
Expected<LTO::RegularLTOState::AddedModule>
LTO::addRegularLTO(BitcodeModule BM, ArrayRef<InputFile::Symbol> Syms,
                   const SymbolResolution *&ResI,
                   const SymbolResolution *ResE) {
  RegularLTOState::AddedModule Mod;
  Expected<std::unique_ptr<Module>> MOrErr =
      BM.getLazyModule(RegularLTO.Ctx, /*ShouldLazyLoadMetadata*/ true,
                       /*IsImporting*/ false);
  if (!MOrErr)
    return MOrErr.takeError();
  Module &M = **MOrErr;
  Mod.M = std::move(*MOrErr);

  if (Error Err = M.materializeMetadata())
    return std::move(Err);

  // If cfi.functions is present and we are in regular LTO mode, LowerTypeTests
  // will rename local functions in the merged module as "<function name>.1".
  // This causes linking errors, since other parts of the module expect the
  // original function name.
  if (LTOMode == LTOK_UnifiedRegular)
    if (NamedMDNode *CfiFunctionsMD = M.getNamedMetadata("cfi.functions"))
      M.eraseNamedMetadata(CfiFunctionsMD);

  UpgradeDebugInfo(M);

  ModuleSymbolTable SymTab;
  SymTab.addModule(&M);

  for (GlobalVariable &GV : M.globals())
    if (GV.hasAppendingLinkage())
      Mod.Keep.push_back(&GV);

  DenseSet<GlobalObject *> AliasedGlobals;
  for (auto &GA : M.aliases())
    if (GlobalObject *GO = GA.getAliaseeObject())
      AliasedGlobals.insert(GO);

  // In this function we need IR GlobalValues matching the symbols in Syms
  // (which is not backed by a module), so we need to enumerate them in the same
  // order. The symbol enumeration order of a ModuleSymbolTable intentionally
  // matches the order of an irsymtab, but when we read the irsymtab in
  // InputFile::create we omit some symbols that are irrelevant to LTO. The
  // Skip() function skips the same symbols from the module as InputFile does
  // from the symbol table.
  auto MsymI = SymTab.symbols().begin(), MsymE = SymTab.symbols().end();
  auto Skip = [&]() {
    while (MsymI != MsymE) {
      auto Flags = SymTab.getSymbolFlags(*MsymI);
      if ((Flags & object::BasicSymbolRef::SF_Global) &&
          !(Flags & object::BasicSymbolRef::SF_FormatSpecific))
        return;
      ++MsymI;
    }
  };
  Skip();

  std::set<const Comdat *> NonPrevailingComdats;
  SmallSet<StringRef, 2> NonPrevailingAsmSymbols;
  for (const InputFile::Symbol &Sym : Syms) {
    assert(ResI != ResE);
    SymbolResolution Res = *ResI++;

    assert(MsymI != MsymE);
    ModuleSymbolTable::Symbol Msym = *MsymI++;
    Skip();

    if (GlobalValue *GV = dyn_cast_if_present<GlobalValue *>(Msym)) {
      if (Res.Prevailing) {
        if (Sym.isUndefined())
          continue;
        Mod.Keep.push_back(GV);
        // For symbols re-defined with linker -wrap and -defsym options,
        // set the linkage to weak to inhibit IPO. The linkage will be
        // restored by the linker.
        if (Res.LinkerRedefined)
          GV->setLinkage(GlobalValue::WeakAnyLinkage);

        GlobalValue::LinkageTypes OriginalLinkage = GV->getLinkage();
        if (GlobalValue::isLinkOnceLinkage(OriginalLinkage))
          GV->setLinkage(GlobalValue::getWeakLinkage(
              GlobalValue::isLinkOnceODRLinkage(OriginalLinkage)));
      } else if (isa<GlobalObject>(GV) &&
                 (GV->hasLinkOnceODRLinkage() || GV->hasWeakODRLinkage() ||
                  GV->hasAvailableExternallyLinkage()) &&
                 !AliasedGlobals.count(cast<GlobalObject>(GV))) {
        // Any of the above three types of linkage indicates that the
        // chosen prevailing symbol will have the same semantics as this copy of
        // the symbol, so we may be able to link it with available_externally
        // linkage. We will decide later whether to do that when we link this
        // module (in linkRegularLTO), based on whether it is undefined.
        Mod.Keep.push_back(GV);
        GV->setLinkage(GlobalValue::AvailableExternallyLinkage);
        if (GV->hasComdat())
          NonPrevailingComdats.insert(GV->getComdat());
        cast<GlobalObject>(GV)->setComdat(nullptr);
      }

      // Set the 'local' flag based on the linker resolution for this symbol.
      if (Res.FinalDefinitionInLinkageUnit) {
        GV->setDSOLocal(true);
        if (GV->hasDLLImportStorageClass())
          GV->setDLLStorageClass(GlobalValue::DLLStorageClassTypes::
                                 DefaultStorageClass);
      }
    } else if (auto *AS =
                   dyn_cast_if_present<ModuleSymbolTable::AsmSymbol *>(Msym)) {
      // Collect non-prevailing symbols.
      if (!Res.Prevailing)
        NonPrevailingAsmSymbols.insert(AS->first);
    } else {
      llvm_unreachable("unknown symbol type");
    }

    // Common resolution: collect the maximum size/alignment over all commons.
    // We also record if we see an instance of a common as prevailing, so that
    // if none is prevailing we can ignore it later.
    if (Sym.isCommon()) {
      // FIXME: We should figure out what to do about commons defined by asm.
      // For now they aren't reported correctly by ModuleSymbolTable.
      auto &CommonRes = RegularLTO.Commons[std::string(Sym.getIRName())];
      CommonRes.Size = std::max(CommonRes.Size, Sym.getCommonSize());
      if (uint32_t SymAlignValue = Sym.getCommonAlignment()) {
        CommonRes.Alignment =
            std::max(Align(SymAlignValue), CommonRes.Alignment);
      }
      CommonRes.Prevailing |= Res.Prevailing;
    }
  }

  if (!M.getComdatSymbolTable().empty())
    for (GlobalValue &GV : M.global_values())
      handleNonPrevailingComdat(GV, NonPrevailingComdats);

  // Prepend ".lto_discard <sym>, <sym>*" directive to each module inline asm
  // block.
  if (!M.getModuleInlineAsm().empty()) {
    std::string NewIA = ".lto_discard";
    if (!NonPrevailingAsmSymbols.empty()) {
      // Don't dicard a symbol if there is a live .symver for it.
      ModuleSymbolTable::CollectAsmSymvers(
          M, [&](StringRef Name, StringRef Alias) {
            if (!NonPrevailingAsmSymbols.count(Alias))
              NonPrevailingAsmSymbols.erase(Name);
          });
      NewIA += " " + llvm::join(NonPrevailingAsmSymbols, ", ");
    }
    NewIA += "\n";
    M.setModuleInlineAsm(NewIA + M.getModuleInlineAsm());
  }

  assert(MsymI == MsymE);
  return std::move(Mod);
}

Error LTO::linkRegularLTO(RegularLTOState::AddedModule Mod,
                          bool LivenessFromIndex) {
  std::vector<GlobalValue *> Keep;
  for (GlobalValue *GV : Mod.Keep) {
    if (LivenessFromIndex && !ThinLTO.CombinedIndex.isGUIDLive(GV->getGUID())) {
      if (Function *F = dyn_cast<Function>(GV)) {
        if (DiagnosticOutputFile) {
          if (Error Err = F->materialize())
            return Err;
          OptimizationRemarkEmitter ORE(F, nullptr);
          ORE.emit(OptimizationRemark(DEBUG_TYPE, "deadfunction", F)
                   << ore::NV("Function", F)
                   << " not added to the combined module ");
        }
      }
      continue;
    }

    if (!GV->hasAvailableExternallyLinkage()) {
      Keep.push_back(GV);
      continue;
    }

    // Only link available_externally definitions if we don't already have a
    // definition.
    GlobalValue *CombinedGV =
        RegularLTO.CombinedModule->getNamedValue(GV->getName());
    if (CombinedGV && !CombinedGV->isDeclaration())
      continue;

    Keep.push_back(GV);
  }

  return RegularLTO.Mover->move(std::move(Mod.M), Keep, nullptr,
                                /* IsPerformingImport */ false);
}

// Add a ThinLTO module to the link.
Error LTO::addThinLTO(BitcodeModule BM, ArrayRef<InputFile::Symbol> Syms,
                      const SymbolResolution *&ResI,
                      const SymbolResolution *ResE) {
  const SymbolResolution *ResITmp = ResI;
  for (const InputFile::Symbol &Sym : Syms) {
    assert(ResITmp != ResE);
    SymbolResolution Res = *ResITmp++;

    if (!Sym.getIRName().empty()) {
      auto GUID = GlobalValue::getGUID(GlobalValue::getGlobalIdentifier(
          Sym.getIRName(), GlobalValue::ExternalLinkage, ""));
      if (Res.Prevailing)
        ThinLTO.PrevailingModuleForGUID[GUID] = BM.getModuleIdentifier();
    }
  }

  if (Error Err =
          BM.readSummary(ThinLTO.CombinedIndex, BM.getModuleIdentifier(),
                         [&](GlobalValue::GUID GUID) {
                           return ThinLTO.PrevailingModuleForGUID[GUID] ==
                                  BM.getModuleIdentifier();
                         }))
    return Err;
  LLVM_DEBUG(dbgs() << "Module " << BM.getModuleIdentifier() << "\n");

  for (const InputFile::Symbol &Sym : Syms) {
    assert(ResI != ResE);
    SymbolResolution Res = *ResI++;

    if (!Sym.getIRName().empty()) {
      auto GUID = GlobalValue::getGUID(GlobalValue::getGlobalIdentifier(
          Sym.getIRName(), GlobalValue::ExternalLinkage, ""));
      if (Res.Prevailing) {
        assert(ThinLTO.PrevailingModuleForGUID[GUID] ==
               BM.getModuleIdentifier());

        // For linker redefined symbols (via --wrap or --defsym) we want to
        // switch the linkage to `weak` to prevent IPOs from happening.
        // Find the summary in the module for this very GV and record the new
        // linkage so that we can switch it when we import the GV.
        if (Res.LinkerRedefined)
          if (auto S = ThinLTO.CombinedIndex.findSummaryInModule(
                  GUID, BM.getModuleIdentifier()))
            S->setLinkage(GlobalValue::WeakAnyLinkage);
      }

      // If the linker resolved the symbol to a local definition then mark it
      // as local in the summary for the module we are adding.
      if (Res.FinalDefinitionInLinkageUnit) {
        if (auto S = ThinLTO.CombinedIndex.findSummaryInModule(
                GUID, BM.getModuleIdentifier())) {
          S->setDSOLocal(true);
        }
      }
    }
  }

  if (!ThinLTO.ModuleMap.insert({BM.getModuleIdentifier(), BM}).second)
    return make_error<StringError>(
        "Expected at most one ThinLTO module per bitcode file",
        inconvertibleErrorCode());

  if (!Conf.ThinLTOModulesToCompile.empty()) {
    if (!ThinLTO.ModulesToCompile)
      ThinLTO.ModulesToCompile = ModuleMapType();
    // This is a fuzzy name matching where only modules with name containing the
    // specified switch values are going to be compiled.
    for (const std::string &Name : Conf.ThinLTOModulesToCompile) {
      if (BM.getModuleIdentifier().contains(Name)) {
        ThinLTO.ModulesToCompile->insert({BM.getModuleIdentifier(), BM});
        llvm::errs() << "[ThinLTO] Selecting " << BM.getModuleIdentifier()
                     << " to compile\n";
      }
    }
  }

  return Error::success();
}

unsigned LTO::getMaxTasks() const {
  CalledGetMaxTasks = true;
  auto ModuleCount = ThinLTO.ModulesToCompile ? ThinLTO.ModulesToCompile->size()
                                              : ThinLTO.ModuleMap.size();
  return RegularLTO.ParallelCodeGenParallelismLevel + ModuleCount;
}

// If only some of the modules were split, we cannot correctly handle
// code that contains type tests or type checked loads.
Error LTO::checkPartiallySplit() {
  if (!ThinLTO.CombinedIndex.partiallySplitLTOUnits())
    return Error::success();

  Function *TypeTestFunc = RegularLTO.CombinedModule->getFunction(
      Intrinsic::getName(Intrinsic::type_test));
  Function *TypeCheckedLoadFunc = RegularLTO.CombinedModule->getFunction(
      Intrinsic::getName(Intrinsic::type_checked_load));
  Function *TypeCheckedLoadRelativeFunc =
      RegularLTO.CombinedModule->getFunction(
          Intrinsic::getName(Intrinsic::type_checked_load_relative));

  // First check if there are type tests / type checked loads in the
  // merged regular LTO module IR.
  if ((TypeTestFunc && !TypeTestFunc->use_empty()) ||
      (TypeCheckedLoadFunc && !TypeCheckedLoadFunc->use_empty()) ||
      (TypeCheckedLoadRelativeFunc &&
       !TypeCheckedLoadRelativeFunc->use_empty()))
    return make_error<StringError>(
        "inconsistent LTO Unit splitting (recompile with -fsplit-lto-unit)",
        inconvertibleErrorCode());

  // Otherwise check if there are any recorded in the combined summary from the
  // ThinLTO modules.
  for (auto &P : ThinLTO.CombinedIndex) {
    for (auto &S : P.second.SummaryList) {
      auto *FS = dyn_cast<FunctionSummary>(S.get());
      if (!FS)
        continue;
      if (!FS->type_test_assume_vcalls().empty() ||
          !FS->type_checked_load_vcalls().empty() ||
          !FS->type_test_assume_const_vcalls().empty() ||
          !FS->type_checked_load_const_vcalls().empty() ||
          !FS->type_tests().empty())
        return make_error<StringError>(
            "inconsistent LTO Unit splitting (recompile with -fsplit-lto-unit)",
            inconvertibleErrorCode());
    }
  }
  return Error::success();
}

Error LTO::run(AddStreamFn AddStream, FileCache Cache) {
  // Compute "dead" symbols, we don't want to import/export these!
  DenseSet<GlobalValue::GUID> GUIDPreservedSymbols;
  DenseMap<GlobalValue::GUID, PrevailingType> GUIDPrevailingResolutions;
  for (auto &Res : *GlobalResolutions) {
    // Normally resolution have IR name of symbol. We can do nothing here
    // otherwise. See comments in GlobalResolution struct for more details.
    if (Res.second.IRName.empty())
      continue;

    GlobalValue::GUID GUID = GlobalValue::getGUID(
        GlobalValue::dropLLVMManglingEscape(Res.second.IRName));

    if (Res.second.VisibleOutsideSummary && Res.second.Prevailing)
      GUIDPreservedSymbols.insert(GUID);

    if (Res.second.ExportDynamic)
      DynamicExportSymbols.insert(GUID);

    GUIDPrevailingResolutions[GUID] =
        Res.second.Prevailing ? PrevailingType::Yes : PrevailingType::No;
  }

  auto isPrevailing = [&](GlobalValue::GUID G) {
    auto It = GUIDPrevailingResolutions.find(G);
    if (It == GUIDPrevailingResolutions.end())
      return PrevailingType::Unknown;
    return It->second;
  };
  computeDeadSymbolsWithConstProp(ThinLTO.CombinedIndex, GUIDPreservedSymbols,
                                  isPrevailing, Conf.OptLevel > 0);

  // Setup output file to emit statistics.
  auto StatsFileOrErr = setupStatsFile(Conf.StatsFile);
  if (!StatsFileOrErr)
    return StatsFileOrErr.takeError();
  std::unique_ptr<ToolOutputFile> StatsFile = std::move(StatsFileOrErr.get());

  // TODO: Ideally this would be controlled automatically by detecting that we
  // are linking with an allocator that supports these interfaces, rather than
  // an internal option (which would still be needed for tests, however). For
  // example, if the library exported a symbol like __malloc_hot_cold the linker
  // could recognize that and set a flag in the lto::Config.
  if (SupportsHotColdNew)
    ThinLTO.CombinedIndex.setWithSupportsHotColdNew();

  Error Result = runRegularLTO(AddStream);
  if (!Result)
    // This will reset the GlobalResolutions optional once done with it to
    // reduce peak memory before importing.
    Result = runThinLTO(AddStream, Cache, GUIDPreservedSymbols);

  if (StatsFile)
    PrintStatisticsJSON(StatsFile->os());

  return Result;
}

void lto::updateMemProfAttributes(Module &Mod,
                                  const ModuleSummaryIndex &Index) {
  if (Index.withSupportsHotColdNew())
    return;

  // The profile matcher applies hotness attributes directly for allocations,
  // and those will cause us to generate calls to the hot/cold interfaces
  // unconditionally. If supports-hot-cold-new was not enabled in the LTO
  // link then assume we don't want these calls (e.g. not linking with
  // the appropriate library, or otherwise trying to disable this behavior).
  for (auto &F : Mod) {
    for (auto &BB : F) {
      for (auto &I : BB) {
        auto *CI = dyn_cast<CallBase>(&I);
        if (!CI)
          continue;
        if (CI->hasFnAttr("memprof"))
          CI->removeFnAttr("memprof");
        // Strip off all memprof metadata as it is no longer needed.
        // Importantly, this avoids the addition of new memprof attributes
        // after inlining propagation.
        // TODO: If we support additional types of MemProf metadata beyond hot
        // and cold, we will need to update the metadata based on the allocator
        // APIs supported instead of completely stripping all.
        CI->setMetadata(LLVMContext::MD_memprof, nullptr);
        CI->setMetadata(LLVMContext::MD_callsite, nullptr);
      }
    }
  }
}

Error LTO::runRegularLTO(AddStreamFn AddStream) {
  // Setup optimization remarks.
  auto DiagFileOrErr = lto::setupLLVMOptimizationRemarks(
      RegularLTO.CombinedModule->getContext(), Conf.RemarksFilename,
      Conf.RemarksPasses, Conf.RemarksFormat, Conf.RemarksWithHotness,
      Conf.RemarksHotnessThreshold);
  LLVM_DEBUG(dbgs() << "Running regular LTO\n");
  if (!DiagFileOrErr)
    return DiagFileOrErr.takeError();
  DiagnosticOutputFile = std::move(*DiagFileOrErr);

  // Finalize linking of regular LTO modules containing summaries now that
  // we have computed liveness information.
  for (auto &M : RegularLTO.ModsWithSummaries)
    if (Error Err = linkRegularLTO(std::move(M),
                                   /*LivenessFromIndex=*/true))
      return Err;

  // Ensure we don't have inconsistently split LTO units with type tests.
  // FIXME: this checks both LTO and ThinLTO. It happens to work as we take
  // this path both cases but eventually this should be split into two and
  // do the ThinLTO checks in `runThinLTO`.
  if (Error Err = checkPartiallySplit())
    return Err;

  // Make sure commons have the right size/alignment: we kept the largest from
  // all the prevailing when adding the inputs, and we apply it here.
  const DataLayout &DL = RegularLTO.CombinedModule->getDataLayout();
  for (auto &I : RegularLTO.Commons) {
    if (!I.second.Prevailing)
      // Don't do anything if no instance of this common was prevailing.
      continue;
    GlobalVariable *OldGV = RegularLTO.CombinedModule->getNamedGlobal(I.first);
    if (OldGV && DL.getTypeAllocSize(OldGV->getValueType()) == I.second.Size) {
      // Don't create a new global if the type is already correct, just make
      // sure the alignment is correct.
      OldGV->setAlignment(I.second.Alignment);
      continue;
    }
    ArrayType *Ty =
        ArrayType::get(Type::getInt8Ty(RegularLTO.Ctx), I.second.Size);
    auto *GV = new GlobalVariable(*RegularLTO.CombinedModule, Ty, false,
                                  GlobalValue::CommonLinkage,
                                  ConstantAggregateZero::get(Ty), "");
    GV->setAlignment(I.second.Alignment);
    if (OldGV) {
      OldGV->replaceAllUsesWith(GV);
      GV->takeName(OldGV);
      OldGV->eraseFromParent();
    } else {
      GV->setName(I.first);
    }
  }

  updateMemProfAttributes(*RegularLTO.CombinedModule, ThinLTO.CombinedIndex);

  bool WholeProgramVisibilityEnabledInLTO =
      Conf.HasWholeProgramVisibility &&
      // If validation is enabled, upgrade visibility only when all vtables
      // have typeinfos.
      (!Conf.ValidateAllVtablesHaveTypeInfos || Conf.AllVtablesHaveTypeInfos);

  // This returns true when the name is local or not defined. Locals are
  // expected to be handled separately.
  auto IsVisibleToRegularObj = [&](StringRef name) {
    auto It = GlobalResolutions->find(name);
    return (It == GlobalResolutions->end() || It->second.VisibleOutsideSummary);
  };

  // If allowed, upgrade public vcall visibility metadata to linkage unit
  // visibility before whole program devirtualization in the optimizer.
  updateVCallVisibilityInModule(
      *RegularLTO.CombinedModule, WholeProgramVisibilityEnabledInLTO,
      DynamicExportSymbols, Conf.ValidateAllVtablesHaveTypeInfos,
      IsVisibleToRegularObj);
  updatePublicTypeTestCalls(*RegularLTO.CombinedModule,
                            WholeProgramVisibilityEnabledInLTO);

  if (Conf.PreOptModuleHook &&
      !Conf.PreOptModuleHook(0, *RegularLTO.CombinedModule))
    return finalizeOptimizationRemarks(std::move(DiagnosticOutputFile));

  if (!Conf.CodeGenOnly) {
    for (const auto &R : *GlobalResolutions) {
      GlobalValue *GV =
          RegularLTO.CombinedModule->getNamedValue(R.second.IRName);
      if (!R.second.isPrevailingIRSymbol())
        continue;
      if (R.second.Partition != 0 &&
          R.second.Partition != GlobalResolution::External)
        continue;

      // Ignore symbols defined in other partitions.
      // Also skip declarations, which are not allowed to have internal linkage.
      if (!GV || GV->hasLocalLinkage() || GV->isDeclaration())
        continue;

      // Symbols that are marked DLLImport or DLLExport should not be
      // internalized, as they are either externally visible or referencing
      // external symbols. Symbols that have AvailableExternally or Appending
      // linkage might be used by future passes and should be kept as is.
      // These linkages are seen in Unified regular LTO, because the process
      // of creating split LTO units introduces symbols with that linkage into
      // one of the created modules. Normally, only the ThinLTO backend would
      // compile this module, but Unified Regular LTO processes both
      // modules created by the splitting process as regular LTO modules.
      if ((LTOMode == LTOKind::LTOK_UnifiedRegular) &&
          ((GV->getDLLStorageClass() != GlobalValue::DefaultStorageClass) ||
           GV->hasAvailableExternallyLinkage() || GV->hasAppendingLinkage()))
        continue;

      GV->setUnnamedAddr(R.second.UnnamedAddr ? GlobalValue::UnnamedAddr::Global
                                              : GlobalValue::UnnamedAddr::None);
      if (EnableLTOInternalization && R.second.Partition == 0)
        GV->setLinkage(GlobalValue::InternalLinkage);
    }

    if (Conf.PostInternalizeModuleHook &&
        !Conf.PostInternalizeModuleHook(0, *RegularLTO.CombinedModule))
      return finalizeOptimizationRemarks(std::move(DiagnosticOutputFile));
  }

  if (!RegularLTO.EmptyCombinedModule || Conf.AlwaysEmitRegularLTOObj) {
    if (Error Err =
            backend(Conf, AddStream, RegularLTO.ParallelCodeGenParallelismLevel,
                    *RegularLTO.CombinedModule, ThinLTO.CombinedIndex))
      return Err;
  }

  return finalizeOptimizationRemarks(std::move(DiagnosticOutputFile));
}

static const char *libcallRoutineNames[] = {
#define HANDLE_LIBCALL(code, name) name,
#include "llvm/IR/RuntimeLibcalls.def"
#undef HANDLE_LIBCALL
};

ArrayRef<const char*> LTO::getRuntimeLibcallSymbols() {
  return ArrayRef(libcallRoutineNames);
}

/// This class defines the interface to the ThinLTO backend.
class lto::ThinBackendProc {
protected:
  const Config &Conf;
  ModuleSummaryIndex &CombinedIndex;
  const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries;
  lto::IndexWriteCallback OnWrite;
  bool ShouldEmitImportsFiles;

public:
  ThinBackendProc(
      const Config &Conf, ModuleSummaryIndex &CombinedIndex,
      const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
      lto::IndexWriteCallback OnWrite, bool ShouldEmitImportsFiles)
      : Conf(Conf), CombinedIndex(CombinedIndex),
        ModuleToDefinedGVSummaries(ModuleToDefinedGVSummaries),
        OnWrite(OnWrite), ShouldEmitImportsFiles(ShouldEmitImportsFiles) {}

  virtual ~ThinBackendProc() = default;
  virtual Error start(
      unsigned Task, BitcodeModule BM,
      const FunctionImporter::ImportMapTy &ImportList,
      const FunctionImporter::ExportSetTy &ExportList,
      const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
      MapVector<StringRef, BitcodeModule> &ModuleMap) = 0;
  virtual Error wait() = 0;
  virtual unsigned getThreadCount() = 0;

  // Write sharded indices and (optionally) imports to disk
  Error emitFiles(const FunctionImporter::ImportMapTy &ImportList,
                  llvm::StringRef ModulePath,
                  const std::string &NewModulePath) {
    return emitFiles(ImportList, ModulePath, NewModulePath + ".thinlto.bc",
                     ShouldEmitImportsFiles ? NewModulePath + ".imports" : "");
  }

  Error emitFiles(const FunctionImporter::ImportMapTy &ImportList,
                  llvm::StringRef ModulePath,
                  const std::string &SummaryPath,
                  const std::string &IndexPath) {
    std::map<std::string, GVSummaryMapTy> ModuleToSummariesForIndex;

    std::error_code EC;
    gatherImportedSummariesForModule(ModulePath, ModuleToDefinedGVSummaries,
                                     ImportList, ModuleToSummariesForIndex);

    raw_fd_ostream OS(SummaryPath, EC, sys::fs::OpenFlags::OF_None);
    if (EC)
      return errorCodeToError(EC);
    writeIndexToFile(CombinedIndex, OS, &ModuleToSummariesForIndex);

    if (!IndexPath.empty()) {
      EC = EmitImportsFiles(ModulePath, IndexPath,
                            ModuleToSummariesForIndex);
      if (EC)
        return errorCodeToError(EC);
    }
    return Error::success();
  }
};

namespace { // OutOfProcessThinBackend

inline constexpr char summary_index_file_suffix[] = ".thinlto.bc";
inline constexpr char imports_file_suffix[] = ".imports";
inline constexpr char native_object_file_suffix[] = ".native.o";

class OutOfProcessThinBackend : public ThinBackendProc {
  DefaultThreadPool BackendThreadPool;
  AddStreamFn AddStream;
  std::set<GlobalValue::GUID> CfiFunctionDefs;
  std::set<GlobalValue::GUID> CfiFunctionDecls;

  std::optional<Error> Err;
  std::mutex ErrMu;

  bool ShouldEmitIndexFiles;

  StringRef LinkerOutputFile;
  SmallString<128> RemoteOptToolPath;
  SmallString<128> DistributorPath;
  bool SaveTemps;
  llvm::DenseMap<llvm::StringRef, llvm::StringRef>* RemappedModules;

  std::vector<std::string> CodegenOptions;
  std::set<std::string> IncludedInputFiles;
  std::string DistributorJson;
  std::string TargetTriple;

  // The information needed to perform a backend compilation.
  struct BackendInfo {
    unsigned Task;
    StringRef MID;
    StringRef ModulePath; // may differ from the MID (ModuleID) e.g. for archive members.
    std::string NativeObjectPath;
    std::string SummaryIndexPath;
    std::string ImportsPath;
    llvm::AddStreamFn AddLinkerInputFn;
    std::vector<std::string> importfiles;
  };
  // The set of backend compilations.
  std::vector<BackendInfo> BackendInfos;

  // A unique string to identify the current project.
  // See uniqueProjectFileSuffix in the DTLTO code.
  StringRef UniqueProjectFileSuffix;

public:
  OutOfProcessThinBackend(
      const Config &Conf, ModuleSummaryIndex &CombinedIndex,
      ThreadPoolStrategy ThinLTOParallelism,
      const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
      AddStreamFn AddStream, FileCache /*Cache*/,
      lto::IndexWriteCallback OnWrite, bool ShouldEmitIndexFiles,
      bool ShouldEmitImportsFiles, StringRef LinkerOutputFile,
      StringRef /*thinLTOCacheDir*/, StringRef RemoteOptTool,
      StringRef Distributor,
      bool SaveTemps, DenseMap<StringRef, StringRef> *RemappedModules,
      StringRef UniqueProjectFileSuffix)
      : ThinBackendProc(Conf, CombinedIndex, ModuleToDefinedGVSummaries,
                        OnWrite, ShouldEmitImportsFiles),
        BackendThreadPool(ThinLTOParallelism), AddStream(std::move(AddStream)),
        ShouldEmitIndexFiles(ShouldEmitIndexFiles),
        LinkerOutputFile(LinkerOutputFile),
        DistributorPath(Distributor), RemoteOptToolPath(RemoteOptTool),
        SaveTemps(SaveTemps), RemappedModules(RemappedModules),
        UniqueProjectFileSuffix(UniqueProjectFileSuffix) {
    for (auto &Name : CombinedIndex.cfiFunctionDefs())
      CfiFunctionDefs.insert(
          GlobalValue::getGUID(GlobalValue::dropLLVMManglingEscape(Name)));
    for (auto &Name : CombinedIndex.cfiFunctionDecls())
      CfiFunctionDecls.insert(
          GlobalValue::getGUID(GlobalValue::dropLLVMManglingEscape(Name)));

    createCommonCC1LevelOptions();

    DistributorJson = LinkerOutputFile.str() + "." + "dist-file.json";
  }

  // Reports an error with an optional message if a file doesn't exist.
  static bool failIfFileNotExist(const llvm::StringRef FilePath,
                                 const llvm::StringRef OptionalMessage = "") {
    if (!llvm::sys::fs::exists(FilePath)) {
      if (!OptionalMessage.empty()) {
        llvm::errs() << " [" + FilePath + "]" << '\n';
      } else {
        llvm::errs() << "File [" + FilePath + "] doesn't exist" << '\n';
      }
      return false;
    }
    return true;
  }

  // Returns working directory for a current process.
  static llvm::SmallString<128> getCurrentProcessWorkingDirectory() {
    llvm::SmallString<128> CurDir;
    std::error_code EC = llvm::sys::fs::current_path(CurDir);
    if (EC) {
      llvm::report_fatal_error(
          "Unable to obtain current process working directory.");
    }
    return CurDir;
  }

  // Most of the command line arguments will be shared between
  // the backend invocations. Set them here:
  //   1. LLD's interface allows for setting -cc1-level options explicitly.
  //   2. LLD -mllvm options set are forwarded, however, -mllvm options that
  //      imply an additional input/output file dependency are unsupported.
  //   3. Any LLD LTO options that affect codegen (e.g.
  //      --lto-sample-profile=<file>) are
  //      translated to -cc1-level options by checking
  //      the LTO Configuratation state that is set from these LLD options.
  //   4. Some -mllvm and -cc1-level options are set to try to ensure that the
  //      default LTO configuration for the opt tool
  //      invocations reasonably matches the default LTO configuration that is
  //      used for ThinLTO in-process backend compilations.
  //   5. Some -cc1-level options that do not affect the codegen, such as
  //      diagnostic format options, are set by LLD to match what would be
  //      expected for the invoked version of LLD.
  bool createCommonCC1LevelOptions() {
    const lto::Config &c = Conf;
    std::vector<std::string> &Ops = CodegenOptions;

    Ops.push_back("-cc1");

    // Forward any LLVM options supplied.
    for (const auto &a : Conf.MllvmArgs) {
      Ops.push_back("-mllvm");
      Ops.push_back(a);
    }

    // Forward and -cc1-level options supplied.
    if (!AdditionalThinLTODCC1Args.empty()) {
      for (auto &a : AdditionalThinLTODCC1Args) {
        Ops.push_back(a);
      }
    }

    Ops.push_back("-O" + std::to_string(Conf.OptLevel));

    if (c.Options.MCOptions.MCIncrementalLinkerCompatible)
      Ops.push_back("-mincremental-linker-compatible");
    if (!c.Options.MCOptions.X86RelaxRelocations)
      Ops.push_back("-mrelax-relocations=no");
    if (c.Options.EmitAddrsig)
      Ops.push_back("-faddrsig");
    if (c.Options.FunctionSections)
      Ops.push_back("-ffunction-sections");
    if (c.Options.DataSections)
      Ops.push_back("-fdata-sections");
    if (c.Options.UniqueBasicBlockSectionNames)
      Ops.push_back("-funique-basic-block-section-names");
    // The allowed values for -fbasic-block-sections= option are the following:
    // {"labels", "all", "list=<file>", "none"}
    if (c.Options.BBSections == BasicBlockSection::None)
      Ops.push_back("-fbasic-block-sections=none");
    if (c.Options.BBSections == BasicBlockSection::Labels)
      Ops.push_back("-fbasic-block-sections=labels");
    if (c.Options.BBSections == BasicBlockSection::All)
      Ops.push_back("-fbasic-block-sections=all");
    if (c.Options.BBSections == BasicBlockSection::List) {
      std::string BBList = "-fbasic-block-sections=list=";
      BBList += c.Options.BBSectionsFuncListBuf->getBufferIdentifier();
      IncludedInputFiles.insert(
          c.Options.BBSectionsFuncListBuf->getBufferIdentifier().str());
      Ops.push_back(BBList);
    }
    if (c.Options.FloatABIType == FloatABI::Hard)
      Ops.push_back("-ffp-model=hard");
    if (c.Options.FloatABIType == FloatABI::Soft)
      Ops.push_back("-ffp-model=soft");

    if (c.RelocModel) {
      Ops.push_back("-mrelocation-model");
      switch (*c.RelocModel) {
      case Reloc::Static:
        Ops.push_back("static");
        break;
      case Reloc::PIC_:
        Ops.push_back("pic");
        break;
      case Reloc::DynamicNoPIC:
        Ops.push_back("dynamic-no-pic");
        break;
      case Reloc::ROPI:
        Ops.push_back("ropi");
        break;
      case Reloc::RWPI:
        Ops.push_back("rwpi");
        break;
      case Reloc::ROPI_RWPI:
        Ops.push_back("ropi_rwpi");
        break;
      }
    }

    if (c.CodeModel) {
      switch (*c.CodeModel) {
      case CodeModel::Kernel:
        Ops.push_back("-mcmodel=kernel");
        break;
      case CodeModel::Large:
        Ops.push_back("-mcmodel=large");
        break;
      case CodeModel::Medium:
        Ops.push_back("-mcmodel=medium");
        break;
      case CodeModel::Small:
        Ops.push_back("-mcmodel=small");
        break;
      case CodeModel::Tiny:
        Ops.push_back("-mcmodel=tiny");
        break;
      }
    }

    // Turn on/off warnings about profile cfg mismatch (default on)
    // --lto-pgo-warn-mismatch.
    if (!c.PGOWarnMismatch)
      Ops.push_back("-mllvm -no-pgo-warn-mismatch");

    // Perform context sensitive PGO instrumentation
    // --lto-cs-profile-generate. Generate instrumented code to collect
    // execution counts into default.profraw file. File name can be overridden
    // by LLVM_PROFILE_FILE environment variable.
    if (c.RunCSIRInstr) {
      Ops.push_back("-fprofile-instrument=csllvm");
      Ops.push_back("-fprofile-instrument-path=default_%m.profraw");
    }
    // Use instrumentation data for profile-guided optimization.
    // Context sensitive profile file path --lto-cs-profile-file=<value>
    if (!c.CSIRProfile.empty()) {
      if (!sys::fs::exists(c.CSIRProfile)) {
        llvm::errs() << "No such file or directory: " + c.CSIRProfile << '\n';
        return false;
      }
      Ops.push_back(
          std::string("-fprofile-instrument-use-path=").append(c.CSIRProfile));
      IncludedInputFiles.insert(c.CSIRProfile);
    }

    // Enable sample-based profile guided optimizations.
    // Sample profile file path --lto-sample-profile=<value>.
    if (!c.SampleProfile.empty()) {
      if (!sys::fs::exists(c.SampleProfile)) {
        llvm::errs() << "No such file or directory: " + c.SampleProfile << '\n';
        return false;
      }
      Ops.push_back(
          std::string("-fprofile-sample-use=").append(c.SampleProfile));
      IncludedInputFiles.insert(c.SampleProfile);
    }

    Ops.push_back("-emit-obj");

    return true;
  }

  // Returns an absolute path made from a current path and a relative
  // path.
  llvm::SmallString<128>
  computeAbsolutePathFromRelative(const llvm::StringRef CurrentFolder,
                                  const llvm::StringRef RelativePath) {
    llvm::Twine CurrentDirectory = CurrentFolder;
    llvm::SmallString<128> RelativeNormalizedPath =
        llvm::StringRef(llvm::sys::path::convert_to_slash(RelativePath));
    llvm::sys::fs::make_absolute(CurrentDirectory, RelativeNormalizedPath);
    llvm::sys::path::remove_dots(RelativeNormalizedPath, true);
    return RelativeNormalizedPath;
  }

  // Makes a canonical path from an input path.
  llvm::SmallString<128> canonicalizePath(llvm::StringRef Path) {
    llvm::SmallString<128> Ret = computeAbsolutePathFromRelative(
        getCurrentProcessWorkingDirectory(), Path);
    if (Ret.empty())
      return Ret;
    llvm::sys::path::native(Ret);
    return Ret;
  }

  // Calculates a full path from an input path.
  std::string calculateFullPathName(const llvm::StringRef Path) {
    llvm::SmallString<128> AbsPath = canonicalizePath(Path);
    return AbsPath.c_str();
  }

  // Computes temporary file path relative to the native object path.
  std::string computeAssociatedFileName(StringRef NativeObjectPath,
                                        StringRef SuffixName) {
    SmallString<256> path;
    sys::path::append(path, NativeObjectPath + SuffixName);
    return path.str().str();
  }

  // Computes native object file path associated with the module.
  std::string computeNativeObjectFileName(StringRef ModulePath) {
    llvm::StringRef ModulePathRef = llvm::StringRef(ModulePath);

    llvm::SmallString<128> ObjFileNameTemplate =
        llvm::sys::path::stem(ModulePathRef);
    ObjFileNameTemplate.append("-%%%%%-%%%%%");

    // When unpacking archive members we add the UniqueProjectFileSuffix.
    // In these cases don't add it again.
    if (!ModulePathRef.contains(UniqueProjectFileSuffix))
      ObjFileNameTemplate.append(llvm::StringRef(UniqueProjectFileSuffix));

    ObjFileNameTemplate.append(native_object_file_suffix);

    llvm::SmallString<128> ObjFilePathModel;
    llvm::sys::path::append(ObjFilePathModel, ObjFileNameTemplate);

    llvm::SmallString<128> ObjFilePath;
    llvm::sys::fs::createUniquePath(ObjFilePathModel, ObjFilePath, false);

    return ObjFilePath.c_str();
  }

  Error addBackendCompilation(const FunctionImporter::ImportMapTy &ImportList,
                              BackendInfo BI) {
    if (auto E =
            emitFiles(ImportList, BI.MID, BI.SummaryIndexPath, BI.ImportsPath))
      return E;

    if (!failIfFileNotExist(BI.ModulePath, "LLVM binary code file doesn't exist")) {
      return make_error<StringError>(BI.MID, inconvertibleErrorCode());
    }

    // Grab the triple from the IR Symtab. All target triples must be the same.
    // TODO: Can we pass this in from the linker?
    // TODO: Should we allow target triples to differ? This would require an
    //       update to the JSON schema to allow a per job triple?
    auto mbOrErr = MemoryBuffer::getFile(BI.ModulePath, /*IsText=*/false,
                                         /*RequiresNullTerminator=*/false);
    if (auto ec = mbOrErr.getError()) {
      return make_error<StringError>("cannot open bitcode file to read triple" +
                                         BI.ModulePath + ": " + ec.message(),
                                     inconvertibleErrorCode());
    }
    MemoryBufferRef mbref = (*mbOrErr)->getMemBufferRef();
    Expected<IRSymtabFile> FOrErr = readIRSymtab(mbref);
    if (!FOrErr)
      return FOrErr.takeError();
    if (!TargetTriple.empty() &&
        TargetTriple != FOrErr->TheReader.getTargetTriple().str())
      return make_error<StringError>(
          "target triple mismatch: Expected:" + TargetTriple +
              " Got:" + FOrErr->TheReader.getTargetTriple().str() +
              " For:" + BI.ModulePath,
          inconvertibleErrorCode());
    TargetTriple = FOrErr->TheReader.getTargetTriple().str();
    BackendInfos.push_back(std::move(BI));
    return Error::success();
  };

  // This function stores the information that will be required for the backend
  // compilations. The backend's wait() function then invokes an external
  // distributor to peform the backend compilations.
  Error runThinLTOBackendThread(
      AddStreamFn AddStream, unsigned Task,
      BitcodeModule BM,
      ModuleSummaryIndex &CombinedIndex,
      const FunctionImporter::ImportMapTy &ImportList,
      const FunctionImporter::ExportSetTy &ExportList,
      const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
      const GVSummaryMapTy &DefinedGlobals,
      MapVector<StringRef, BitcodeModule> &ModuleMap) {

    BackendInfo BI = {Task, BM.getModuleIdentifier(),
                      (RemappedModules && RemappedModules->contains(BM.getModuleIdentifier()))
                          ? RemappedModules->at(BM.getModuleIdentifier())
                          : BM.getModuleIdentifier()};
    BI.NativeObjectPath = computeNativeObjectFileName(BI.ModulePath),
    BI.SummaryIndexPath = computeAssociatedFileName(BI.NativeObjectPath,
                                                    summary_index_file_suffix);
    BI.ImportsPath =
        computeAssociatedFileName(BI.NativeObjectPath, imports_file_suffix);

    return addBackendCompilation(ImportList, std::move(BI));
  }

  Error start(
      unsigned Task, BitcodeModule BM,
      const FunctionImporter::ImportMapTy &ImportList,
      const FunctionImporter::ExportSetTy &ExportList,
      const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
      MapVector<StringRef, BitcodeModule> &ModuleMap) override {

    StringRef ModulePath = BM.getModuleIdentifier();
    assert(ModuleToDefinedGVSummaries.count(ModulePath));
    const GVSummaryMapTy &DefinedGlobals =
        ModuleToDefinedGVSummaries.find(ModulePath)->second;

    // Run serially to ensure deterministic ordering.
    // TODO: Run multi-threaded. Upstream comments mention that
    //       this might be important for performance:
    //       https://github.com/llvm/llvm-project/pull/109847.
    Error E = runThinLTOBackendThread(AddStream, Task, BM, CombinedIndex,
                                      ImportList, ExportList, ResolvedODR,
                                      DefinedGlobals, ModuleMap);
    if (E) {
      std::unique_lock<std::mutex> L(ErrMu);
      if (Err)
        Err = joinErrors(std::move(*Err), std::move(E));
      else
        Err = std::move(E);
    }

    if (OnWrite)
      OnWrite(std::string(ModulePath));
    return Error::success();
  }

  // If RapidJson doesn't support special symbols we will have to replace them
  // before writing a string to Json. RapidJson used in LLVM replaces special
  // symbols automatically, so currently this function is just a placeholder.
  static std::string toJsonString(const std::string &Name) { return Name; }

  // Adds escape symbols around the path name, if the path contains tabs or
  // spaces.
  static std::string toJsonPath(const std::string &Name) {
    auto Pos = Name.find_first_of(" \t");
    if (Pos == Name.npos)
      return Name;
    std::stringstream SS;
    SS << '\"';
    SS << Name;
    SS << '\"';
    return SS.str();
  }

  llvm::BumpPtrAllocator bAlloc;
  llvm::StringSaver saver{bAlloc};

  // Generates build script and writes it into a JSON file.
  bool generateBuildScript() {

    const bool USE_ABSOLUTE_PATH = false;

    // Versioning.
    llvm::json::Object VersionObj;
    VersionObj["major"] = 0;
    VersionObj["minor"] = 0;

    // Information common to all jobs note that we use a custom
    // syntax for referencing by index into the job input and output
    // file arrays. I have just hardcoded the indicies for now so there is
    // a coupling between this code and the order that the files
    // are added to those arrays.
    llvm::json::Object CommonObj;
    // Command line to perform codegen using clang compiler.
    auto clangPath = [&]() -> std::string {
      std::stringstream Command;
      Command << toJsonPath(getClangPath().str());
      return Command.str();
    };
    CommonObj["codegen-tool"] = clangPath();

    llvm::MapVector<StringRef, std::pair<StringRef, size_t>> moduleMap;
    auto addModuleMap = [&](StringRef id, StringRef path) -> size_t {
      if (!moduleMap.contains(id)) {
        moduleMap.insert({id, {path, moduleMap.size()}});
      }
      return moduleMap[id].second;
    };

    // Add a command line template that can be used
    // for each job.
    {
      llvm::json::Array ArgsArray; // "args"

      for (const std::string &CGOption : CodegenOptions)
        ArgsArray.push_back(CGOption);

      ArgsArray.push_back("-o");
      // reference to BI.NativeObjectPath
      {
        llvm::json::Array A;
        A.push_back("");
        A.push_back("outputs");
        A.push_back(0);
        ArgsArray.push_back(std::move(A));
      }

      ArgsArray.push_back("-x");
      ArgsArray.push_back("ir");
      // reference to BI.ModulePath
      {
        llvm::json::Array A;
        A.push_back("");
        A.push_back("inputs");
        A.push_back(0);
        ArgsArray.push_back(std::move(A));
      }

      // reference to BI.SummaryIndexPath
      {
        llvm::json::Array A;
        A.push_back("-fthinlto-index=");
        A.push_back("inputs");
        A.push_back(1);
        ArgsArray.push_back(std::move(A));
      }

      ArgsArray.push_back("-triple");
      ArgsArray.push_back(toJsonPath(TargetTriple));

      // TODO: This will create a number of additional output
      //       files. Do we need to tell the distributors about
      //       those files?
      if (SaveTemps)
        ArgsArray.push_back("-save-temps=cwd");

      CommonObj["args"] = std::move(ArgsArray);
    }

    // Add the input files common to all jobs.
    {
      llvm::json::Array InputsArray; // "inputs"
      for (const std::string &Incl : IncludedInputFiles) {
        InputsArray.push_back(toJsonPath(Incl));
      }
      CommonObj["inputs"] = std::move(InputsArray);
    }

    std::vector<llvm::json::Object> JobsObject;
    for (auto &BI : BackendInfos) {
      llvm::json::Object JobObject;
      std::vector<std::string> remap;

      // Note that there is a coupling between the
      // order that these files appear in this
      // array and the references hard coded in
      // the "common" object's "args" property.
      {
        llvm::json::Array InputsArray; // "inputs"

        // referenced as ["", "inputs", 0]
        InputsArray.push_back(addModuleMap(BI.MID, BI.ModulePath));

        // referenced as ["-fthinlto-index=", "inputs", 1]
        InputsArray.push_back(toJsonPath(BI.SummaryIndexPath));

        // Add the import files. These files are not mentioned
        // on the command line but are referenced via the combined
        // summary index shard.
        for (const std::string &ImportFileName : BI.importfiles) {
          std::string ImportFilePath = RemappedModules->contains(ImportFileName)
                                           ? RemappedModules->at(ImportFileName).str()
                                           : ImportFileName;
          ImportFilePath = USE_ABSOLUTE_PATH
                               ? calculateFullPathName(ImportFilePath)
                               : ImportFilePath;
          InputsArray.push_back(
              addModuleMap(ImportFileName, saver.save(ImportFilePath)));
        }

        JobObject["inputs"] = std::move(InputsArray);
      }

      // Note that there is a coupling between the
      // order that these files appear in this
      // array and the references hard coded in
      // the "common" object's "args" property.
      {
        llvm::json::Array OutputsArray; // "outputs"

        // referenced as ["", "outputs", 0]
        OutputsArray.push_back(toJsonPath(BI.NativeObjectPath));

        JobObject["outputs"] = std::move(OutputsArray);
      }

      JobsObject.push_back(std::move(JobObject));
    }

    // We store the set of modules here so that they can
    // be referred to be index elsewhere in the JSON document
    // to avoid duplication.
    // In most cases the ModuldeID is the path on disk to
    // the bitcode file for the module. Where this is not
    // true (e.g. if there are archive members or thin
    // archive members) write out remapping information.
    {
      llvm::json::Array ModulesArray; // "modules"
      for (auto &I : moduleMap) {
        auto &id = I.first;
        auto &path = I.second.first;
        if (id == path) {
          ModulesArray.push_back(id.str());
        } else {
          llvm::json::Array RemapArray;
          RemapArray.push_back(id.str());
          RemapArray.push_back(toJsonPath(path.str()));
          ModulesArray.push_back(std::move(RemapArray));
        }
      }
      CommonObj["modules"] = std::move(ModulesArray);
    }

    std::error_code EC;
    llvm::raw_fd_ostream OS(DistributorJson, EC);
    if (EC)
      return false;

    // TODO: LLVM supports pretty printer, we could do that.
    //       llvm::json::OStream js(OS);
    size_t Idx = 0;
    OS << "{"
       << llvm::json::toJSON(
              std::optional<llvm::StringRef>(llvm::StringRef("version")))
       << ":" << llvm::json::Value(std::move(VersionObj)) << ",\n"
       << llvm::json::toJSON(
              std::optional<llvm::StringRef>(llvm::StringRef("common")))
       << ":" << llvm::json::Value(std::move(CommonObj)) << ",\n"
       << llvm::json::toJSON(std::optional<llvm::StringRef>("jobs")) << ": [\n";
    for (llvm::json::Object &Obj : JobsObject) {
      OS << "  " << llvm::json::Value(std::move(Obj));
      if (++Idx < JobsObject.size())
        OS << ",\n";
      else
        OS << "\n";
    }
    OS << "]}\n";
    OS.flush();

    return true;
  }

  enum class ToolStatus {
    NO_ERRORS = 0x00,
    TOOL_DOES_NOT_EXIST,
    UNABLE_TO_EXECUTE_TOOL,
    TOOL_RETURNED_ERROR,
    MISSING_OUTPUT_OBJECT_FILE,
  };

  class ToolReturnCode {
    ToolStatus Status = ToolStatus::NO_ERRORS;
    int ExitCode = 0;

  public:
    ToolReturnCode() : Status{ToolStatus::NO_ERRORS}, ExitCode{0} {}
    ToolReturnCode(ToolStatus ST, int EC = 0) : Status{ST}, ExitCode{EC} {}

    ToolReturnCode(const ToolReturnCode &RC) = default;
    ToolReturnCode(ToolReturnCode &&RC) = default;

    ToolReturnCode &operator=(const ToolReturnCode &RC) = default;

    ToolStatus toolStatus() const { return Status; }
    int exitCode() const { return ExitCode; }

    void toolStatus(ToolStatus TS) { Status = TS; }
    void exitCode(int EC) { ExitCode = EC; }
  };

  ToolReturnCode runDistributor() {
    llvm::SmallString<128> DistributorScriptPath;
    std::string JsonFilePath = DistributorJson;
    llvm::SmallVector<llvm::StringRef, 3> DistributorOptions = {
        DistributorPath};
    if (!DistributorScriptPath.empty()) {
      DistributorOptions.push_back(DistributorScriptPath);
    }
    if (!AdditionalThinLTODistributorArgs.empty()) {
      for (auto &a : AdditionalThinLTODistributorArgs)
        DistributorOptions.push_back(a);
    }
    DistributorOptions.push_back(JsonFilePath);

    // Run the distributor
    llvm::sys::ProcessInfo PI = llvm::sys::ExecuteNoWait(
        DistributorPath, DistributorOptions,
        /*Env=*/std::nullopt, /*Redirects=*/{}, /*MemoryLimit=*/0,
        /*ErrMsg=*/nullptr, /*ExecutionFailed=*/nullptr,
        /*AffinityMask=*/nullptr, /*DetachProcess=*/false);
    if (PI.Pid == llvm::sys::ProcessInfo::InvalidPid) {
      return ToolReturnCode(ToolStatus::UNABLE_TO_EXECUTE_TOOL);
    }

    llvm::sys::ProcessInfo PIW = llvm::sys::Wait(PI, std::nullopt);
    if (PIW.ReturnCode != 0) {
      return ToolReturnCode(ToolStatus::TOOL_RETURNED_ERROR, PIW.ReturnCode);
    }

    bool RC = true;

    // Check that all output files were returned to us by the distributor.
    for (auto &BI : BackendInfos) {
      const std::string &ObjectFilePath = BI.NativeObjectPath;

      // If because of whatever reason the distributor doesn't return back a
      // generated native object file, we could fall back to multi-process mode
      // and re-do codegen for this and any other modules that couldn't be
      // generated. We could warn the user about potential link-time degradation
      // and recover from distributor-related failures.
      if (!llvm::sys::fs::exists(ObjectFilePath)) {
        RC = false;
      }
    }
    return RC ? ToolReturnCode(ToolStatus::NO_ERRORS)
              : ToolReturnCode(ToolStatus::MISSING_OUTPUT_OBJECT_FILE);
  }

  static inline llvm::StringRef warn_unable_to_do_dtlto =
      "Unable to do distributed ThinLTO";

  // Prints error or warning diagnostics based on the tool kind and tool
  // status.
  bool ToolErrorReportPrint(const ToolReturnCode &ReturnCode) {
    auto printWarnOrError = [&](const llvm::Twine &Arg) -> void {
      llvm::errs() << Arg << "\n";
    };

    switch (ReturnCode.toolStatus()) {
    case ToolStatus::TOOL_DOES_NOT_EXIST:
      printWarnOrError("Can't find distributor; " + warn_unable_to_do_dtlto);
      break;
    case ToolStatus::UNABLE_TO_EXECUTE_TOOL:
      printWarnOrError("Unable to execute distributor; " +
                       warn_unable_to_do_dtlto);
      break;
    case ToolStatus::TOOL_RETURNED_ERROR:
      printWarnOrError("distributor returned an error code " +
                       std::to_string(ReturnCode.exitCode()) + "; " +
                       warn_unable_to_do_dtlto);
      break;
    case ToolStatus::MISSING_OUTPUT_OBJECT_FILE: {
      for (auto &BI : BackendInfos) {
        const std::string &ObjectFilePath = BI.NativeObjectPath;
        printWarnOrError("distributor didn't return back native object file " +
                         ObjectFilePath);
      }
      break;
    }
    case ToolStatus::NO_ERRORS:
      break;
    };

    return ReturnCode.toolStatus() == ToolStatus::NO_ERRORS;
  }

  // Initializes LTOOptions.ClangExecutableFilePath variable.
  ToolReturnCode resolveClangExecutablePath(const llvm::StringRef Prefix) {
    if (RemoteOptToolPath.empty())
      return ToolReturnCode(ToolStatus::TOOL_DOES_NOT_EXIST);
    return ToolReturnCode(ToolStatus::NO_ERRORS);
  }

  // Get Clang Path
  StringRef getClangPath() {
    resolveClangExecutablePath("prospero");
    if (RemoteOptToolPath.empty()) {
      llvm::errs()
          << "Unable to determine a file path for the clang executable.\n";
      return "";
    }
    return RemoteOptToolPath;
  }

  // Invoke distributor to do the backend compilations and cleanup any temporary files.
  Error wait() override {
    if (BackendInfos.empty())
      return Error::success();

    // Load the imported files list from the import files emitted earlier.
    // TODO: Pass this information in memory instead.
    for (auto &BI : BackendInfos) {
      llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> fileBuf =
          llvm::MemoryBuffer::getFile(BI.ImportsPath, /*IsText=*/true);
      if (!fileBuf) {
        return make_error<StringError>("GetImportFiles error: " +
                                           BI.ImportsPath,
                                       inconvertibleErrorCode());
      }
      StringRef StrRef = fileBuf.get()->getBuffer();
      llvm::SmallVector<llvm::StringRef, 32> Lines;
      StrRef.split(Lines, "\n");
      for (auto L : Lines) {
        if (L.trim().empty())
          continue;
        BI.importfiles.push_back(L.trim().str());
      }
    }

    // Invoke distributor to do the backend compilations.
    {
      llvm::StringRef BCError = "backend compilation error";

      if (generateBuildScript()) {
        llvm::TimeTraceScope timeScope(
            "STAGE 3: [Distributed ThinLTO, codegen, Distributor]");
        ToolReturnCode RC = runDistributor();
        if (!ToolErrorReportPrint(RC)) {
          return make_error<StringError>(BCError, inconvertibleErrorCode());
        }
      } else {
        return make_error<StringError>(
            BCError + ": Failed to generate distributor JSON script " +
                DistributorJson,
            inconvertibleErrorCode());
      }
    }

    for (auto &BI : BackendInfos) {
      Expected<std::unique_ptr<CachedFileStream>> StreamOrErr =
          AddStream(BI.Task, BI.MID);
      if (Error Err = StreamOrErr.takeError())
        report_fatal_error(std::move(Err));
      std::unique_ptr<CachedFileStream> Stream = std::move(*StreamOrErr);
      std::string ObjectFilenameForDebug = Stream->ObjectPathName;

      // Load the native object from a file into a memory buffer
      // and store its contents in the output buffer.
      // TODO: Implement populating cache entries.
      llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> objFileMbOrErr =
          MemoryBuffer::getFile(BI.NativeObjectPath, false, false);
      if (std::error_code ec = objFileMbOrErr.getError()) {
        return make_error<StringError>(
            "Cannot open native object file: " + BI.NativeObjectPath + ": " +
                ec.message(),
            inconvertibleErrorCode());
      }
    }

    if (SaveTemps)
      return Error::success();

    // Clean up temporary files. We want to remove any files that wouldn't be
    // created by the InProcessBackend. This is potentially slow.
    // TODO: Could we deffer to the OS or build system somehow?
    // TODO: Do this asynchronously.
    auto removeOneFile = [](llvm::StringRef FileName) -> void {
      std::error_code EC = sys::fs::remove(FileName, true);
      if (EC &&
          EC != std::make_error_code(std::errc::no_such_file_or_directory)) {
        llvm::errs() << "Can't remove the file " << FileName << " "
                     << EC.message() << "\n";
        return;
      }
      LLVM_DEBUG(llvm::outs() << "File " << FileName << " removed.\n");
    };
    for (auto &BI : BackendInfos) {
      removeOneFile(BI.NativeObjectPath);
      if (!ShouldEmitImportsFiles)
        removeOneFile(BI.ImportsPath);
      if (!ShouldEmitIndexFiles)
        removeOneFile(BI.SummaryIndexPath);
      removeOneFile(DistributorJson);
    }

    return Error::success();
  }

  // return 1 to prevent module  re-ordering and avoid non-determinism.
  // TODO: Use concurrency when populating the backend compilation information.
  unsigned getThreadCount() override { return 1; }
};
} // namespace

namespace {
class InProcessThinBackend : public ThinBackendProc {
  DefaultThreadPool BackendThreadPool;
  AddStreamFn AddStream;
  FileCache Cache;
  std::set<GlobalValue::GUID> CfiFunctionDefs;
  std::set<GlobalValue::GUID> CfiFunctionDecls;

  std::optional<Error> Err;
  std::mutex ErrMu;

  bool ShouldEmitIndexFiles;

public:
  InProcessThinBackend(
      const Config &Conf, ModuleSummaryIndex &CombinedIndex,
      ThreadPoolStrategy ThinLTOParallelism,
      const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
      AddStreamFn AddStream, FileCache Cache, lto::IndexWriteCallback OnWrite,
      bool ShouldEmitIndexFiles, bool ShouldEmitImportsFiles)
      : ThinBackendProc(Conf, CombinedIndex, ModuleToDefinedGVSummaries,
                        OnWrite, ShouldEmitImportsFiles),
        BackendThreadPool(ThinLTOParallelism), AddStream(std::move(AddStream)),
        Cache(std::move(Cache)), ShouldEmitIndexFiles(ShouldEmitIndexFiles) {
    for (auto &Name : CombinedIndex.cfiFunctionDefs())
      CfiFunctionDefs.insert(
          GlobalValue::getGUID(GlobalValue::dropLLVMManglingEscape(Name)));
    for (auto &Name : CombinedIndex.cfiFunctionDecls())
      CfiFunctionDecls.insert(
          GlobalValue::getGUID(GlobalValue::dropLLVMManglingEscape(Name)));
  }

  Error runThinLTOBackendThread(
      AddStreamFn AddStream, FileCache Cache, unsigned Task, BitcodeModule BM,
      ModuleSummaryIndex &CombinedIndex,
      const FunctionImporter::ImportMapTy &ImportList,
      const FunctionImporter::ExportSetTy &ExportList,
      const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
      const GVSummaryMapTy &DefinedGlobals,
      MapVector<StringRef, BitcodeModule> &ModuleMap) {
    auto RunThinBackend = [&](AddStreamFn AddStream) {
      LTOLLVMContext BackendContext(Conf);
      Expected<std::unique_ptr<Module>> MOrErr = BM.parseModule(BackendContext);
      if (!MOrErr)
        return MOrErr.takeError();

      return thinBackend(Conf, Task, AddStream, **MOrErr, CombinedIndex,
                         ImportList, DefinedGlobals, &ModuleMap);
    };

    auto ModuleID = BM.getModuleIdentifier();

    if (ShouldEmitIndexFiles) {
      if (auto E = emitFiles(ImportList, ModuleID, ModuleID.str()))
        return E;
    }

    if (!Cache || !CombinedIndex.modulePaths().count(ModuleID) ||
        all_of(CombinedIndex.getModuleHash(ModuleID),
               [](uint32_t V) { return V == 0; }))
      // Cache disabled or no entry for this module in the combined index or
      // no module hash.
      return RunThinBackend(AddStream);

    SmallString<40> Key;
    // The module may be cached, this helps handling it.
    computeLTOCacheKey(Key, Conf, CombinedIndex, ModuleID, ImportList,
                       ExportList, ResolvedODR, DefinedGlobals, CfiFunctionDefs,
                       CfiFunctionDecls, std::nullopt);
    Expected<AddStreamFn> CacheAddStreamOrErr =
        Cache(Task, Key, ModuleID, std::nullopt /*FileToMove*/);
    if (Error Err = CacheAddStreamOrErr.takeError())
      return Err;
    AddStreamFn &CacheAddStream = *CacheAddStreamOrErr;
    if (CacheAddStream)
      return RunThinBackend(CacheAddStream);

    return Error::success();
  }

  Error start(
      unsigned Task, BitcodeModule BM,
      const FunctionImporter::ImportMapTy &ImportList,
      const FunctionImporter::ExportSetTy &ExportList,
      const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
      MapVector<StringRef, BitcodeModule> &ModuleMap) override {
    StringRef ModulePath = BM.getModuleIdentifier();
    assert(ModuleToDefinedGVSummaries.count(ModulePath));
    const GVSummaryMapTy &DefinedGlobals =
        ModuleToDefinedGVSummaries.find(ModulePath)->second;
    BackendThreadPool.async(
        [=](BitcodeModule BM, ModuleSummaryIndex &CombinedIndex,
            const FunctionImporter::ImportMapTy &ImportList,
            const FunctionImporter::ExportSetTy &ExportList,
            const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes>
                &ResolvedODR,
            const GVSummaryMapTy &DefinedGlobals,
            MapVector<StringRef, BitcodeModule> &ModuleMap) {
          if (LLVM_ENABLE_THREADS && Conf.TimeTraceEnabled)
            timeTraceProfilerInitialize(Conf.TimeTraceGranularity,
                                        "thin backend");
          Error E = runThinLTOBackendThread(
              AddStream, Cache, Task, BM, CombinedIndex, ImportList, ExportList,
              ResolvedODR, DefinedGlobals, ModuleMap);
          if (E) {
            std::unique_lock<std::mutex> L(ErrMu);
            if (Err)
              Err = joinErrors(std::move(*Err), std::move(E));
            else
              Err = std::move(E);
          }
          if (LLVM_ENABLE_THREADS && Conf.TimeTraceEnabled)
            timeTraceProfilerFinishThread();
        },
        BM, std::ref(CombinedIndex), std::ref(ImportList), std::ref(ExportList),
        std::ref(ResolvedODR), std::ref(DefinedGlobals), std::ref(ModuleMap));

    if (OnWrite)
      OnWrite(std::string(ModulePath));
    return Error::success();
  }

  Error wait() override {
    BackendThreadPool.wait();
    if (Err)
      return std::move(*Err);
    else
      return Error::success();
  }

  unsigned getThreadCount() override {
    return BackendThreadPool.getMaxConcurrency();
  }
};
} // end anonymous namespace

ThinBackend lto::createOutOfProcessThinBackend(ThreadPoolStrategy Parallelism,
                                               lto::IndexWriteCallback OnWrite,
                                               bool ShouldEmitIndexFiles,
                                               bool ShouldEmitImportsFiles,
                                               StringRef LinkerOutputFile,
                                               StringRef thinLTOCacheDir,
                                               StringRef RemoteOptTool,
                                               StringRef Distributor, bool SaveTemps,
                                               DenseMap<StringRef, StringRef>* RemappedModules,
                                               StringRef UniqueProjectFileSuffix) {
  return
      [=](const Config &Conf, ModuleSummaryIndex &CombinedIndex,
          const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
          AddStreamFn AddStream, FileCache Cache) {
        return std::make_unique<OutOfProcessThinBackend>(
            Conf, CombinedIndex, Parallelism, ModuleToDefinedGVSummaries,
            AddStream, Cache, OnWrite, ShouldEmitIndexFiles,
            ShouldEmitImportsFiles, LinkerOutputFile, thinLTOCacheDir,
            RemoteOptTool, Distributor, SaveTemps, RemappedModules, UniqueProjectFileSuffix);
      };
}

ThinBackend lto::createInProcessThinBackend(ThreadPoolStrategy Parallelism,
                                            lto::IndexWriteCallback OnWrite,
                                            bool ShouldEmitIndexFiles,
                                            bool ShouldEmitImportsFiles) {
  return
      [=](const Config &Conf, ModuleSummaryIndex &CombinedIndex,
          const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
          AddStreamFn AddStream, FileCache Cache) {
        return std::make_unique<InProcessThinBackend>(
            Conf, CombinedIndex, Parallelism, ModuleToDefinedGVSummaries,
            AddStream, Cache, OnWrite, ShouldEmitIndexFiles,
            ShouldEmitImportsFiles);
      };
}

StringLiteral lto::getThinLTODefaultCPU(const Triple &TheTriple) {
  if (!TheTriple.isOSDarwin())
    return "";
  if (TheTriple.getArch() == Triple::x86_64)
    return "core2";
  if (TheTriple.getArch() == Triple::x86)
    return "yonah";
  if (TheTriple.isArm64e())
    return "apple-a12";
  if (TheTriple.getArch() == Triple::aarch64 ||
      TheTriple.getArch() == Triple::aarch64_32)
    return "cyclone";
  return "";
}

// Given the original \p Path to an output file, replace any path
// prefix matching \p OldPrefix with \p NewPrefix. Also, create the
// resulting directory if it does not yet exist.
std::string lto::getThinLTOOutputFile(StringRef Path, StringRef OldPrefix,
                                      StringRef NewPrefix) {
  if (OldPrefix.empty() && NewPrefix.empty())
    return std::string(Path);
  SmallString<128> NewPath(Path);
  llvm::sys::path::replace_path_prefix(NewPath, OldPrefix, NewPrefix);
  StringRef ParentPath = llvm::sys::path::parent_path(NewPath.str());
  if (!ParentPath.empty()) {
    // Make sure the new directory exists, creating it if necessary.
    if (std::error_code EC = llvm::sys::fs::create_directories(ParentPath))
      llvm::errs() << "warning: could not create directory '" << ParentPath
                   << "': " << EC.message() << '\n';
  }
  return std::string(NewPath);
}

namespace {
class WriteIndexesThinBackend : public ThinBackendProc {
  std::string OldPrefix, NewPrefix, NativeObjectPrefix;
  raw_fd_ostream *LinkedObjectsFile;

public:
  WriteIndexesThinBackend(
      const Config &Conf, ModuleSummaryIndex &CombinedIndex,
      const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
      std::string OldPrefix, std::string NewPrefix,
      std::string NativeObjectPrefix, bool ShouldEmitImportsFiles,
      raw_fd_ostream *LinkedObjectsFile, lto::IndexWriteCallback OnWrite)
      : ThinBackendProc(Conf, CombinedIndex, ModuleToDefinedGVSummaries,
                        OnWrite, ShouldEmitImportsFiles),
        OldPrefix(OldPrefix), NewPrefix(NewPrefix),
        NativeObjectPrefix(NativeObjectPrefix),
        LinkedObjectsFile(LinkedObjectsFile) {}

  Error start(
      unsigned Task, BitcodeModule BM,
      const FunctionImporter::ImportMapTy &ImportList,
      const FunctionImporter::ExportSetTy &ExportList,
      const std::map<GlobalValue::GUID, GlobalValue::LinkageTypes> &ResolvedODR,
      MapVector<StringRef, BitcodeModule> &ModuleMap) override {
    StringRef ModulePath = BM.getModuleIdentifier();
    std::string NewModulePath =
        getThinLTOOutputFile(ModulePath, OldPrefix, NewPrefix);

    if (LinkedObjectsFile) {
      std::string ObjectPrefix =
          NativeObjectPrefix.empty() ? NewPrefix : NativeObjectPrefix;
      std::string LinkedObjectsFilePath =
          getThinLTOOutputFile(ModulePath, OldPrefix, ObjectPrefix);
      *LinkedObjectsFile << LinkedObjectsFilePath << '\n';
    }

    if (auto E = emitFiles(ImportList, ModulePath, NewModulePath))
      return E;

    if (OnWrite)
      OnWrite(std::string(ModulePath));
    return Error::success();
  }

  Error wait() override { return Error::success(); }

  // WriteIndexesThinBackend should always return 1 to prevent module
  // re-ordering and avoid non-determinism in the final link.
  unsigned getThreadCount() override { return 1; }
};
} // end anonymous namespace

ThinBackend lto::createWriteIndexesThinBackend(
    std::string OldPrefix, std::string NewPrefix,
    std::string NativeObjectPrefix, bool ShouldEmitImportsFiles,
    raw_fd_ostream *LinkedObjectsFile, IndexWriteCallback OnWrite) {
  return
      [=](const Config &Conf, ModuleSummaryIndex &CombinedIndex,
          const DenseMap<StringRef, GVSummaryMapTy> &ModuleToDefinedGVSummaries,
          AddStreamFn AddStream, FileCache Cache) {
        return std::make_unique<WriteIndexesThinBackend>(
            Conf, CombinedIndex, ModuleToDefinedGVSummaries, OldPrefix,
            NewPrefix, NativeObjectPrefix, ShouldEmitImportsFiles,
            LinkedObjectsFile, OnWrite);
      };
}

Error LTO::runThinLTO(AddStreamFn AddStream, FileCache Cache,
                      const DenseSet<GlobalValue::GUID> &GUIDPreservedSymbols) {
  LLVM_DEBUG(dbgs() << "Running ThinLTO\n");
  ThinLTO.CombinedIndex.releaseTemporaryMemory();
  timeTraceProfilerBegin("ThinLink", StringRef(""));
  auto TimeTraceScopeExit = llvm::make_scope_exit([]() {
    if (llvm::timeTraceProfilerEnabled())
      llvm::timeTraceProfilerEnd();
  });
  if (ThinLTO.ModuleMap.empty())
    return Error::success();

  if (ThinLTO.ModulesToCompile && ThinLTO.ModulesToCompile->empty()) {
    llvm::errs() << "warning: [ThinLTO] No module compiled\n";
    return Error::success();
  }

  if (Conf.CombinedIndexHook &&
      !Conf.CombinedIndexHook(ThinLTO.CombinedIndex, GUIDPreservedSymbols))
    return Error::success();

  // Collect for each module the list of function it defines (GUID ->
  // Summary).
  DenseMap<StringRef, GVSummaryMapTy> ModuleToDefinedGVSummaries(
      ThinLTO.ModuleMap.size());
  ThinLTO.CombinedIndex.collectDefinedGVSummariesPerModule(
      ModuleToDefinedGVSummaries);
  // Create entries for any modules that didn't have any GV summaries
  // (either they didn't have any GVs to start with, or we suppressed
  // generation of the summaries because they e.g. had inline assembly
  // uses that couldn't be promoted/renamed on export). This is so
  // InProcessThinBackend::start can still launch a backend thread, which
  // is passed the map of summaries for the module, without any special
  // handling for this case.
  for (auto &Mod : ThinLTO.ModuleMap)
    if (!ModuleToDefinedGVSummaries.count(Mod.first))
      ModuleToDefinedGVSummaries.try_emplace(Mod.first);

  // Synthesize entry counts for functions in the CombinedIndex.
  computeSyntheticCounts(ThinLTO.CombinedIndex);

  DenseMap<StringRef, FunctionImporter::ImportMapTy> ImportLists(
      ThinLTO.ModuleMap.size());
  DenseMap<StringRef, FunctionImporter::ExportSetTy> ExportLists(
      ThinLTO.ModuleMap.size());
  StringMap<std::map<GlobalValue::GUID, GlobalValue::LinkageTypes>> ResolvedODR;

  if (DumpThinCGSCCs)
    ThinLTO.CombinedIndex.dumpSCCs(outs());

  std::set<GlobalValue::GUID> ExportedGUIDs;

  bool WholeProgramVisibilityEnabledInLTO =
      Conf.HasWholeProgramVisibility &&
      // If validation is enabled, upgrade visibility only when all vtables
      // have typeinfos.
      (!Conf.ValidateAllVtablesHaveTypeInfos || Conf.AllVtablesHaveTypeInfos);
  if (hasWholeProgramVisibility(WholeProgramVisibilityEnabledInLTO))
    ThinLTO.CombinedIndex.setWithWholeProgramVisibility();

  // If we're validating, get the vtable symbols that should not be
  // upgraded because they correspond to typeIDs outside of index-based
  // WPD info.
  DenseSet<GlobalValue::GUID> VisibleToRegularObjSymbols;
  if (WholeProgramVisibilityEnabledInLTO &&
      Conf.ValidateAllVtablesHaveTypeInfos) {
    // This returns true when the name is local or not defined. Locals are
    // expected to be handled separately.
    auto IsVisibleToRegularObj = [&](StringRef name) {
      auto It = GlobalResolutions->find(name);
      return (It == GlobalResolutions->end() ||
              It->second.VisibleOutsideSummary);
    };

    getVisibleToRegularObjVtableGUIDs(ThinLTO.CombinedIndex,
                                      VisibleToRegularObjSymbols,
                                      IsVisibleToRegularObj);
  }

  // If allowed, upgrade public vcall visibility to linkage unit visibility in
  // the summaries before whole program devirtualization below.
  updateVCallVisibilityInIndex(
      ThinLTO.CombinedIndex, WholeProgramVisibilityEnabledInLTO,
      DynamicExportSymbols, VisibleToRegularObjSymbols);

  // Perform index-based WPD. This will return immediately if there are
  // no index entries in the typeIdMetadata map (e.g. if we are instead
  // performing IR-based WPD in hybrid regular/thin LTO mode).
  std::map<ValueInfo, std::vector<VTableSlotSummary>> LocalWPDTargetsMap;
  runWholeProgramDevirtOnIndex(ThinLTO.CombinedIndex, ExportedGUIDs,
                               LocalWPDTargetsMap);

  auto isPrevailing = [&](GlobalValue::GUID GUID, const GlobalValueSummary *S) {
    return ThinLTO.PrevailingModuleForGUID[GUID] == S->modulePath();
  };
  if (EnableMemProfContextDisambiguation) {
    MemProfContextDisambiguation ContextDisambiguation;
    ContextDisambiguation.run(ThinLTO.CombinedIndex, isPrevailing);
  }

  // Figure out which symbols need to be internalized. This also needs to happen
  // at -O0 because summary-based DCE is implemented using internalization, and
  // we must apply DCE consistently with the full LTO module in order to avoid
  // undefined references during the final link.
  for (auto &Res : *GlobalResolutions) {
    // If the symbol does not have external references or it is not prevailing,
    // then not need to mark it as exported from a ThinLTO partition.
    if (Res.second.Partition != GlobalResolution::External ||
        !Res.second.isPrevailingIRSymbol())
      continue;
    auto GUID = GlobalValue::getGUID(
        GlobalValue::dropLLVMManglingEscape(Res.second.IRName));
    // Mark exported unless index-based analysis determined it to be dead.
    if (ThinLTO.CombinedIndex.isGUIDLive(GUID))
      ExportedGUIDs.insert(GUID);
  }

  // Reset the GlobalResolutions to deallocate the associated memory, as there
  // are no further accesses. We specifically want to do this before computing
  // cross module importing, which adds to peak memory via the computed import
  // and export lists.
  GlobalResolutions.reset();

  if (Conf.OptLevel > 0)
    ComputeCrossModuleImport(ThinLTO.CombinedIndex, ModuleToDefinedGVSummaries,
                             isPrevailing, ImportLists, ExportLists);

  // Any functions referenced by the jump table in the regular LTO object must
  // be exported.
  for (auto &Def : ThinLTO.CombinedIndex.cfiFunctionDefs())
    ExportedGUIDs.insert(
        GlobalValue::getGUID(GlobalValue::dropLLVMManglingEscape(Def)));
  for (auto &Decl : ThinLTO.CombinedIndex.cfiFunctionDecls())
    ExportedGUIDs.insert(
        GlobalValue::getGUID(GlobalValue::dropLLVMManglingEscape(Decl)));

  auto isExported = [&](StringRef ModuleIdentifier, ValueInfo VI) {
    const auto &ExportList = ExportLists.find(ModuleIdentifier);
    return (ExportList != ExportLists.end() && ExportList->second.count(VI)) ||
           ExportedGUIDs.count(VI.getGUID());
  };

  // Update local devirtualized targets that were exported by cross-module
  // importing or by other devirtualizations marked in the ExportedGUIDs set.
  updateIndexWPDForExports(ThinLTO.CombinedIndex, isExported,
                           LocalWPDTargetsMap);

  thinLTOInternalizeAndPromoteInIndex(ThinLTO.CombinedIndex, isExported,
                                      isPrevailing);

  auto recordNewLinkage = [&](StringRef ModuleIdentifier,
                              GlobalValue::GUID GUID,
                              GlobalValue::LinkageTypes NewLinkage) {
    ResolvedODR[ModuleIdentifier][GUID] = NewLinkage;
  };
  thinLTOResolvePrevailingInIndex(Conf, ThinLTO.CombinedIndex, isPrevailing,
                                  recordNewLinkage, GUIDPreservedSymbols);

  thinLTOPropagateFunctionAttrs(ThinLTO.CombinedIndex, isPrevailing);

  generateParamAccessSummary(ThinLTO.CombinedIndex);

  if (llvm::timeTraceProfilerEnabled())
    llvm::timeTraceProfilerEnd();

  TimeTraceScopeExit.release();

  std::unique_ptr<ThinBackendProc> BackendProc =
      ThinLTO.Backend(Conf, ThinLTO.CombinedIndex, ModuleToDefinedGVSummaries,
                      AddStream, Cache);

  auto &ModuleMap =
      ThinLTO.ModulesToCompile ? *ThinLTO.ModulesToCompile : ThinLTO.ModuleMap;

  auto ProcessOneModule = [&](int I) -> Error {
    auto &Mod = *(ModuleMap.begin() + I);
    // Tasks 0 through ParallelCodeGenParallelismLevel-1 are reserved for
    // combined module and parallel code generation partitions.
    return BackendProc->start(RegularLTO.ParallelCodeGenParallelismLevel + I,
                              Mod.second, ImportLists[Mod.first],
                              ExportLists[Mod.first], ResolvedODR[Mod.first],
                              ThinLTO.ModuleMap);
  };

  if (BackendProc->getThreadCount() == 1) {
    // Process the modules in the order they were provided on the command-line.
    // It is important for this codepath to be used for WriteIndexesThinBackend,
    // to ensure the emitted LinkedObjectsFile lists ThinLTO objects in the same
    // order as the inputs, which otherwise would affect the final link order.
    for (int I = 0, E = ModuleMap.size(); I != E; ++I)
      if (Error E = ProcessOneModule(I))
        return E;
  } else {
    // When executing in parallel, process largest bitsize modules first to
    // improve parallelism, and avoid starving the thread pool near the end.
    // This saves about 15 sec on a 36-core machine while link `clang.exe` (out
    // of 100 sec).
    std::vector<BitcodeModule *> ModulesVec;
    ModulesVec.reserve(ModuleMap.size());
    for (auto &Mod : ModuleMap)
      ModulesVec.push_back(&Mod.second);
    for (int I : generateModulesOrdering(ModulesVec))
      if (Error E = ProcessOneModule(I))
        return E;
  }
  return BackendProc->wait();
}

Expected<std::unique_ptr<ToolOutputFile>> lto::setupLLVMOptimizationRemarks(
    LLVMContext &Context, StringRef RemarksFilename, StringRef RemarksPasses,
    StringRef RemarksFormat, bool RemarksWithHotness,
    std::optional<uint64_t> RemarksHotnessThreshold, int Count) {
  std::string Filename = std::string(RemarksFilename);
  // For ThinLTO, file.opt.<format> becomes
  // file.opt.<format>.thin.<num>.<format>.
  if (!Filename.empty() && Count != -1)
    Filename =
        (Twine(Filename) + ".thin." + llvm::utostr(Count) + "." + RemarksFormat)
            .str();

  auto ResultOrErr = llvm::setupLLVMOptimizationRemarks(
      Context, Filename, RemarksPasses, RemarksFormat, RemarksWithHotness,
      RemarksHotnessThreshold);
  if (Error E = ResultOrErr.takeError())
    return std::move(E);

  if (*ResultOrErr)
    (*ResultOrErr)->keep();

  return ResultOrErr;
}

Expected<std::unique_ptr<ToolOutputFile>>
lto::setupStatsFile(StringRef StatsFilename) {
  // Setup output file to emit statistics.
  if (StatsFilename.empty())
    return nullptr;

  llvm::EnableStatistics(false);
  std::error_code EC;
  auto StatsFile =
      std::make_unique<ToolOutputFile>(StatsFilename, EC, sys::fs::OF_None);
  if (EC)
    return errorCodeToError(EC);

  StatsFile->keep();
  return std::move(StatsFile);
}

// Compute the ordering we will process the inputs: the rough heuristic here
// is to sort them per size so that the largest module get schedule as soon as
// possible. This is purely a compile-time optimization.
std::vector<int> lto::generateModulesOrdering(ArrayRef<BitcodeModule *> R) {
  auto Seq = llvm::seq<int>(0, R.size());
  std::vector<int> ModulesOrdering(Seq.begin(), Seq.end());
  llvm::sort(ModulesOrdering, [&](int LeftIndex, int RightIndex) {
    auto LSize = R[LeftIndex]->getBuffer().size();
    auto RSize = R[RightIndex]->getBuffer().size();
    return LSize > RSize;
  });
  return ModulesOrdering;
}
