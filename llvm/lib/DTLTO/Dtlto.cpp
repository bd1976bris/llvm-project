
#include "llvm/DTLTO/Dtlto.h"

#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/LTO/LTO.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MemoryBufferRef.h"
#include "llvm/Support/Path.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"

#include <string>

using namespace llvm;

namespace dtlto {

struct TempFilesRemover {
  std::vector<std::string> Files;
  ~TempFilesRemover() { removeFiles(); }

public:
  void add(const llvm::StringRef File) { Files.push_back(File.str()); }
  void removeFiles() {
    auto removeFile = [](llvm::StringRef FileName) -> void {
      std::error_code EC = sys::fs::remove(FileName, true);
      if (EC &&
          EC != std::make_error_code(std::errc::no_such_file_or_directory)) {
        llvm::errs() << "Error while removing the file: " << FileName << " : "
                     << EC.message() << "\n";
      }
    };
    for (const auto &File : Files)
      removeFile(File);
  }
};

// This will call TempFilesRemover class destructor when the current process
// is about to terminate.
static llvm::ManagedStatic<TempFilesRemover> StaticTempFilesRemover;

// Atomically writes a contents of a memory buffer into a file.
static llvm::Error saveBuffer(StringRef FileBuffer, StringRef FilePath) {
  SmallString<64> UniquePathModel{FilePath, ".%%%-%%%.tmp"};
  SmallString<64> TempFilePath;
  sys::fs::createUniquePath(UniquePathModel, TempFilePath, false);

  std::error_code EC;
  raw_fd_ostream OS(TempFilePath.str(), EC, sys::fs::OpenFlags::OF_None);
  if (EC) {
    return createStringError("Can't create file %s, error %s",
                             TempFilePath.c_str(), EC.message().c_str());
  }
  OS.write(FileBuffer.data(), FileBuffer.size());
  OS.close();
  // Rename temporary file into a real one.
  EC = sys::fs::rename(TempFilePath, FilePath);
  if (EC) {
    sys::fs::remove(TempFilePath);
    return createStringError("Can't rename file %s to %s, error %s",
                             TempFilePath.c_str(), FilePath.data(),
                             EC.message().c_str());
  }
  return Error::success();
}

// Checks if the input file is a member of an archive. If it is, this function
// generates a new module ID, updates the module identifier, and saves the
// memory buffer into a file that has new module ID name.
Error saveInputArchiveMember(lto::LTO *LtoObj, lto::InputFile *Input,
                             const std::string &TimeNow) {
  StringRef ModuleId = Input->getName();
  std::string UID = utohexstr(sys::Process::getProcessId());

  bool IsMemberOfArchive = Input->getInputFileType() ==
                           lto::InputFile::InputFileType::SOLID_ARCHIVE_MEMBER;
  // If the file does not exist, assume it is an archive member.
  if (!sys::fs::exists(ModuleId)) {
    if (!IsMemberOfArchive)
      UID = TimeNow;
    IsMemberOfArchive = true;
  }

  if (IsMemberOfArchive) {
    MemoryBufferRef MemoryBufferRef = Input->getFileBuffer();
    // Generate a new module ID from a file name part of original module ID with
    // the process ID appended to it.
    SmallString<64> NewModuleId{sys::path::filename(ModuleId), ".", UID, ".o"};
    BitcodeModule &BM = Input->getSingleBitcodeModule();
    BM.setModuleIdentifier(LtoObj->Saver.save(NewModuleId.str()));
    StaticTempFilesRemover->add(BM.getModuleIdentifier());
    if (Error EC = saveBuffer(MemoryBufferRef.getBuffer(), NewModuleId))
      return EC;
  }
  return Error::success();
}
// Iterate through the list of input files.
Error saveInputArchiveMembers(lto::LTO *LtoObj) {
  auto Duration = std::chrono::system_clock::now().time_since_epoch();
  auto Nsecs = std::chrono::duration_cast<std::chrono::nanoseconds>(Duration);
  std::string TimeNow = utohexstr(Nsecs.count());

  for (auto &Input : LtoObj->InputFiles) {
    if (Error EC = saveInputArchiveMember(LtoObj, Input.get(), TimeNow))
      return EC;
  }
  return Error::success();
}

llvm::Error run(llvm::lto::LTO &LtoObj) {
  if (LtoObj.Dtlto)
    if (Error EC = saveInputArchiveMembers(&LtoObj))
      return EC;
  return Error::success();
}

} // namespace dtlto
