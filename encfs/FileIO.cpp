#include "FileIO.h"

namespace encfs {
  FileIO::FileIO() = default;
  FileIO::~FileIO() = default;

  unsigned int FileIO::blockSize() const { return 1; }

  bool FileIO::setIV(uint64_t iv) {
    (void) iv;
    return true;
  }
}
