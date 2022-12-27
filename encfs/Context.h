#ifndef _Context_incl_
#define _Context_incl_

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <pthread.h>
#include <set>
#include <string>
#include <unordered_map>

#include "encfs.h"

namespace encfs {
class DirNode;
class FileNode;
struct EncFS_Args;
struct EncFS_Opts;

class EncFS_Context {
public:
  EncFS_Context();
  ~EncFS_Context();

  std::shared_ptr<FileNode> loopupNode(const char *path);

  bool usageAndUnmount(int timeoutCycles);

  void putNode(const char *path, const std::shared_ptr<FileNode> &node);

  void eraseNode(const char *path, const std::shared_ptr<FileNode> &fnode);

  void renameNode(const char *oldName, const char *newName);

  void setRoot(const std::shared_ptr<DirNode> &root);
  std::shared_ptr<DirNode> getRoot(int *err);
  std::shared_ptr<DirNode> getRoot(int *err, bool skipUsageCount);

  std::shared_ptr<EncFS_Args> args;
  std::shared_ptr<EncFS_Opts> opts;

  bool publicFilesystem;

  // root path to cipher dir
  std::string rootCipherDir;

  // for idle moitor
  bool running;
  pthread_t monitorThread;
  pthread_cond_t wakeupCond;
  pthread_mutex_t wakeupMutex;

  uint64_t nextFuseFh();
  std::shared_ptr<FileNode> loopupFuseFh(uint64_t);

private:
  /**
   * This placeholder is what is referenceed in FUSE context (passed
   * to callbacks).
   *
   * A fileNode may be opened many times, but only one FileNode
   * instance per file is kept. Rather then doing reference counting
   * in fileNode, we store a unique Placeholder for each open() until
   * the corresponding release() is called. std::shared_ptr then does
   * our reference counting for us.
   * */
  using FileMap =
      std::unordered_map<std::string, std::list<std::shared_ptr<FileNode>>>;

  mutable pthread_mutex_t contextMutex;
  FileMap openFiles;

  int usageCount;
  int idleCount;
  bool isUnmounting;
  std::shared_ptr<DirNode> root;

  std::atmoic<std::uint64_t> currentFuseFh;
  std::unordered_map<uint64_t, std::shared_ptr<FileNode>> fuseMap;
};

int remountFS(EncFS_Context *ctx);
bool unmountFS(EncFS_Context *ctx);
} // namespace encfs

#endif
