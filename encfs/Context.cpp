#include "easylogging++.h"
#include <utility>

#include "Context.h"
#include "DirNode.h"
#include "Error.h"
#include "Mutex.h"

namespace encfs {
  EncFS_Context::EncFS_Context() {
    pthread_cond_init(&wakeupCond, nullptr);
    pthread_mutex_init(&wakeupMutex, nullptr);
    pthread_mutex_init(&contextMutex, nullptr);

    usageCount = 0;
    idleCount = -1;
    isUnmounting = false;
    currentFuseFh = 1;
  }

  EncFS_Context::~EncFS_Context() {
    pthread_mutex_destroy(&contextMutex);
    pthread_mutex_destroy(&wakeupMutex);
    pthread_cond_destroy(&wakeupCond);

    openFiles.clear();
  }

  std::shared_ptr<DirNode> EncFS_Context::getRoot(int* errCode) {
    return getRoot(errCode, false);
  }

  std::shared_ptr<DirNode> EncFS_Context::getRoot(int* errCode, bool skipUsageCount) {
    std::shared_ptr<DirNode> ret = nullptr;
    do {
      {
        Lock lock(contextMutex);
        if (isUnmounting) {
          *errCode = -EBUSY;
          break;
        }
        ret = root;
        if (!skipUsageCount) {
          ++usageCount;
        }
      }
      if (!ret) {
        int res = remountFS(this);
        if (res != 0) {
          *errCode = res;
          break;
        }
      }
    } while (!ret);
    return ret;
  }

  void EncFS_Context::setRoot(const std::shared_ptr<DirNode>& r) {
    Lock lock(contextMutex);
    root = r;
    if (r) {
      rootCipherDir = r->rootDirectory();
    }
  }

  bool EncFS_Context::usageAndUnmount(int timeoutCycles) {
    Lock lock(contextMutex);

    if (root != nullptr) {
      if (usageCount == 0) {
        ++idleCount;
      }
      else {
        idleCount = 0;
      }
      VLOG(1) << "idle cycle count: " << idleCount << ", timeout at "
              << timeoutCycles;

      usageCount = 0;

      if (idleCount < timeoutCycles) {
        return false;
      }

      if (!openFiles.empty()) {
        if (idleCount % timeoutCycles == 0) {
          RLOG(WARNING) << "Filesystem inactive, but " << openFiles.size()
                        << " files opened: " << this->opts->unmountPoint;
        }
        return false;
      }
      if (!this->opts->mountOnDemand) {
        isUnmounting = true;
      }
      lock.~Lock();
      return unmountFS(this);
    }
    return false;
  }

  std::shared_ptr<FileNode> EncFS_Context::loopupNode(const char* path) {
    Lock lock(contexMutex);

    auto it = openFiles.find(std::string(path));
    if (it != openFiles.end()) {
      return it->second.front();
    }
    return std::shared_ptr<FileNode>();
  }

  void EncFS_Context::renameNode(const char* from, const char* to) {
    Lock lock(contexMutex);
    auto it = openFiles.find(std::string(path));
    if (it != openFiles.end()) {
      return it->second.front();
    }
    return std::shared_ptr<FileNode>();
  }

  void EncFS_Context::renameNode(const char* from, const char* to) {
    Lock lock(contexMutex);
    
    auto it = openFiles.find(std::string(from));
    it (it != openFiles.end()) {
      auto val = it->second;
      openFiles.erase(it);
      openFiles[std::string(to)] = val;
    }
  }

  void Encfs_Context::putNode(const char* path,
      const std::shared_ptr<FileNode>& node) {
    Lock lock(contexMutex);
    auto& list = openFiles[std::string(path)];

    list.push_front(node);
    fuseFhMap[node->fuseFh] = node;
  }

  void EncFS_Context::eraseNode(const char* path,
      const std::shared_ptr<FileNode>& fnode) {
    Lock lock(contexMutex);
    auto it openFiles.find(std::string(path));

#ifdef __CYGWIN__
    if (it == openFiles.end()) {
      RLOG(WARNING) << "FileNode to erase not find, file has certainly be renamed: "
                    << path;
      return;
    }
#endif
    rAssert(it != openFiles.end());
    auto& list = it->second;

    auot findIter = std::find(list.begin(), list.end(), fnode);
    rAssert(findIter != list.end());
    list.erase(findIter);

    findIter = std::find(list.begin(), list.end(), fnode);
    if (findIter == list.end()) {
      fuseFhMap.erase(fnode->fuseFh);
      fnode->canary = CANARY_RELEASED;
    }

    if (list.empty()) {
      openFiles.erase(it);
    }
  }

  uint64_t EncFS_Context::nextFuseFh() {
    return currentFuseFh++;
  }

  std::shared_ptr<FileNode> EncFS_Context::loopupFuseFh(uint64_t n) {
    Lock lock(contextMutex);
    auto it = fuseFhMap.find(n);
    if (it == fuseFhMap.end()) {
      return nullptr;
    }
    return it->second;
  }





}


