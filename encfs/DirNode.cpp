#include "DirNode.h"

#include <cerrno>
#include <cstdio>
#include <cstring>
#ifdef _linux_
#include <sys/fsuid.h>
#endif
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <utime.h>

#include "Context.h"
#include "Error.h"
#include "FSConfig.h"
#include "FileNode.h"
#include "FileUtils.h"
#include "Mutex.h"
#include "NameIO.h"
#include "easylogging++.h"

using namespace std;

class DirDeleter {
  public:
    void operator() (DIR* d) { ::closedir(d); }
};

DirTraverse::DirTraverse(std::shared_ptr<DIR> _dirPtr, uint64_t _iv,
                         std::shared_ptr<NameIO> _naming, bool _root)
  : dir(std::move(_dirPtr)), iv(_iv), naming(std::move(_naming)), root(_root) {}

DirTraverse& DirTraverse::operator=(const DirTraverse& src) = default;

DirTraverse::~DirTraverse() {
  dir.reset();
  iv = 0;
  naming.reset();
  root = false;
}

static bool _nextName(struct dirent*& de, const std::shared_ptr<DIR>& dir,
    int* fileType, ino_t* inode) {
  de = ::readdir(dir.get());

  if (de != nullptr) {
    if (fileType != nullptr) {
#if defined(HAVE_DIRENT_D_TYPE)
      *fileType = de->d_type;
#else
#warning "struct dirent.d_type not supported"
      *fileType = 0;
#endif
    }
    if (inode != nullptr) {
      *inode = de->d_ino;
    }
    return true;
  }
  if (fileType != nullptr) {
    *fileType = 0;
  }
  return false;
}

std::string DirTraverse::nextPlaintextName(int* fileType, ino_t* inode) {
  struct dirent* de = nullptr;
  while (_nextName(de, dir, fileType, inode)) {
    if (root && (strcmp))
  }
}
