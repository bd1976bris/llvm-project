//===- Dtlto.cpp - Distributed ThinLTO implementation --------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// \file
// This file implements support functions for Distributed ThinLTO, focusing on
// archive file handling.
//
//===----------------------------------------------------------------------===//

#include "llvm/DTLTO/DTLTO.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/BinaryFormat/Magic.h"
#include "llvm/LTO/LTO.h"
#include "llvm/Object/Archive.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBufferRef.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"
#ifdef _WIN32
#include "llvm/Support/Windows/WindowsSupport.h"
#endif

#include <iostream>
#include <string>

using namespace llvm;

namespace {

// Writes the content of a memory buffer into a file.
llvm::Error saveBuffer(StringRef FileBuffer, StringRef FilePath) {
  std::error_code EC;
  raw_fd_ostream OS(FilePath.str(), EC, sys::fs::OpenFlags::OF_None);
  if (EC) {
    return createStringError(inconvertibleErrorCode(),
                             "Failed to create file %s: %s", FilePath.data(),
                             EC.message().c_str());
  }
  OS.write(FileBuffer.data(), FileBuffer.size());
  if (OS.has_error()) {
    return createStringError(inconvertibleErrorCode(),
                             "Failed writing to file %s", FilePath.data());
  }
  return Error::success();
}

// Compute the file path for a thin archive member.
//
// For thin archives, an archive member name is typically a file path relative
// to the archive file's directory. This function resolves that path.
SmallString<64> computeThinArchiveMemberPath(const StringRef ArchivePath,
                                             const StringRef MemberName) {
  assert(!ArchivePath.empty() && "An archive file path must be non empty.");
  SmallString<64> MemberPath;
  if (sys::path::is_relative(MemberName)) {
    MemberPath = sys::path::parent_path(ArchivePath);
    sys::path::append(MemberPath, MemberName);
  } else
    MemberPath = MemberName;
  sys::path::remove_dots(MemberPath, /*remove_dot_dot=*/true);
  return MemberPath;
}

} // namespace

// Determines if a file at the given path is a thin archive file.
//
// This function uses a cache to avoid repeatedly reading the same file.
// It reads only the header portion (magic bytes) of the file to identify
// the archive type.
Expected<bool> lto::DTLTO::isThinArchive(const StringRef ArchivePath) {
  // Return cached result if available.
  auto Cached = ArchiveFiles.find(ArchivePath);
  if (Cached != ArchiveFiles.end())
    return Cached->second;

  uint64_t FileSize = -1;
  bool IsThin = false;
  std::error_code EC = sys::fs::file_size(ArchivePath, FileSize);
  if (EC)
    return createStringError(inconvertibleErrorCode(),
                             "Failed to get file size from archive %s: %s",
                             ArchivePath.data(), EC.message().c_str());
  if (FileSize < sizeof(object::ThinArchiveMagic))
    return createStringError(inconvertibleErrorCode(),
                             "Archive file size is too small %s",
                             ArchivePath.data());

  // Read only the first few bytes containing the magic signature.
  ErrorOr<std::unique_ptr<MemoryBuffer>> MemBufferOrError =
      MemoryBuffer::getFileSlice(ArchivePath, sizeof(object::ThinArchiveMagic),
                                 0);

  if ((EC = MemBufferOrError.getError()))
    return createStringError(inconvertibleErrorCode(),
                             "Failed to read from archive %s: %s",
                             ArchivePath.data(), EC.message().c_str());

  StringRef MemBuf = (*MemBufferOrError.get()).getBuffer();
  if (file_magic::archive != identify_magic(MemBuf))
    return createStringError(inconvertibleErrorCode(),
                             "Unknown format for archive %s",
                             ArchivePath.data());

  IsThin = MemBuf.starts_with(object::ThinArchiveMagic);

  // Cache the result
  ArchiveFiles[ArchivePath] = IsThin;
  return IsThin;
}

// Removes any temporary regular archive member files that were created during
// processing.
void lto::DTLTO::removeTempFiles() {
  for (auto &Input : InputFiles) {
    if (Input->isMemberOfArchive())
      sys::fs::remove(Input->getName(), /*IgnoreNonExisting=*/true);
  }
}

static Expected<StringRef> normalizePath(StringRef Path, StringSaver &Saver) {
#if defined(_WIN32)
  SmallString<128> Expanded;
  if (std::error_code EC = llvm::sys::windows::makeLongPath(Path, Expanded))
    return createStringError(inconvertibleErrorCode(),
                             "Normalisation failed for identifier %s: %s",
                             Path.str().c_str(), EC.message().c_str());
  return Saver.save(Expanded.str());
#else
  (void)Saver;
  return Path;
#endif
}

// This function performs the following tasks:
// 1. Adds the input file to the LTO object's list of input files.
// 2. Normalizes paths to remove any Windows short-path components.
// 3. For thin archive members, generates a new module ID which is a path to a
// thin archive member file.
// 4. For regular archive members, generates a new unique module ID.
// 5. Updates the bitcode module's identifier.
Expected<std::shared_ptr<lto::InputFile>>
lto::DTLTO::addInput(std::unique_ptr<lto::InputFile> InputPtr) {
  // Add the input file to the LTO object.
  InputFiles.emplace_back(InputPtr.release());
  auto &Input = InputFiles.back();
  BitcodeModule &BM = Input->getSingleBitcodeModule();

  auto Norm = [&](StringRef S) -> Expected<StringRef> {
    if (S.empty())
      return S;
    return normalizePath(S, Saver);
  };

  StringRef ArchivePath = Input->getArchivePath();

  // Non-archive member input files.
  if (ArchivePath.empty()) {
    auto Id = Norm(Input->getName());
    if (!Id)
      return Id.takeError();
    BM.setModuleIdentifier(*Id);
    return Input;
  }

  auto ArchivePathN = Norm(ArchivePath);
  if (!ArchivePathN)
    return ArchivePathN.takeError();
  auto IsThin = isThinArchive(*ArchivePathN);
  if (!IsThin)
    return IsThin.takeError();

  SmallString<64> NewModuleId;
  if (*IsThin) {
    // For thin archives, use the path to the actual file.
    NewModuleId =
        computeThinArchiveMemberPath(*ArchivePathN, Input->getMemberName());
    auto LongId = Norm(NewModuleId.str());
    if (!LongId)
      return LongId.takeError();
    BM.setModuleIdentifier(*LongId);
  } else {
    // For regular archives, generate a unique name using process ID and
    // sequence number.
    Input->memberOfArchive(true);

    // Normalize directory then reattach original filename. The directory
    // will exist but the filename won't exit yet.
    SmallString<256> Dir = sys::path::parent_path(Input->getName());
    auto DirN = Norm(Dir.str());
    if (!DirN)
      return DirN.takeError();
    SmallString<256> NewPath(*DirN);
    sys::path::append(NewPath, sys::path::filename(Input->getName()));

    const std::string Seq = std::to_string(InputFiles.size());
    const std::string PID = utohexstr(sys::Process::getProcessId());

    NewModuleId = {NewPath.str(), ".", Seq, ".", PID, ".o"};
    BM.setModuleIdentifier(Saver.save(NewModuleId.str()));
  }

  return Input;
}

// Write the archive member content to a file named after the module ID.
// If a file with that name already exists, it's likely a leftover from a
// previously terminated linker process and can be safely overwritten.
Error lto::DTLTO::saveInputArchiveMember(lto::InputFile *Input) {
  StringRef ModuleId = Input->getName();
  if (Input->isMemberOfArchive()) {
    MemoryBufferRef MemoryBufferRef = Input->getFileBuffer();
    if (Error EC = saveBuffer(MemoryBufferRef.getBuffer(), ModuleId))
      return EC;
  }
  return Error::success();
}

// Iterates through all ThinLTO-enabled input files and saves their content
// to separate files if they are regular archive members.
Error lto::DTLTO::saveInputArchiveMembers() {
  for (auto &Input : InputFiles) {
    if (!Input->isThinLTO())
      continue;
    if (Error EC = saveInputArchiveMember(Input.get()))
      return EC;
  }
  return Error::success();
}

// Entry point for DTLTO archives support.
//
// Sets up the temporary file remover and processes archive members.
// Must be called after all inputs are added but before optimization begins.
llvm::Error lto::DTLTO::handleArchiveInputs() {

  // Process and save archive members to separate files if needed.
  if (Error EC = saveInputArchiveMembers())
    return EC;
  return Error::success();
}
