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
    if (root && (strcmp(".encfs6.xml", de->d_name) == 0)) {
      VLOG(1) << "skipping filename: " << de->d_name;
    }
  }
  return string();
}

std::string DirTraverse::nextInvalid() {
  struct dirent* de = nullptr;

  while (_nextName(de, dir, (int*)nullptr, (ino_t*)nullptr)) {
    if (root && (strcmp(".encfs6.xml", de->d_name) == 0)) {
      VLOG(1) << "skipping filename; " << de->d_name;
      continue;
    }
    try {
      uint64_t localIv = iv;
      naming->decodePath(de->d_name, &localIv);
      continue;
    } catch (encfs::Error& ex) {
      return string(de->d_name);
    }
  }
  return string();
}

struct RenameEl {
  string oldCName;
  string newCName;

  string oldPName;
  string newPName;

  bool isDirectory;
};

class RenameOp {
  private:
    DirNode* dn;
    std::shared_ptr<list<RenameEl>> renameList;
    list<RenameEl>::const_iterator last;

  public:
    RenameOp(DirNode* _dn, std::shared_ptr<list<RenameEl>> _renameList)
      : dn(_dn), renameList(std::move(_renameList)) {
        last = renameList->begin();
      }
    ~RenameOp();

    RenameOp(const RenameOp& src) = delete;
    RenameOp(RenameOp&& other) = delete;
    RenameOp& operator=(const RenameOp& other) = delete;
    RenameOp& operator=(RenameOp&& other) = delete;

    explicit operator bool() const { return renameList != nullptr; }

    bool apply();
    void undo();
}

RenameOp::~RenameOp() {
  if (renameList) {
    list <RenameEl>::iterator it;
    for (it = renameList->begin(); it != renameList->end(); ++it) {
      it->oldPName.assign(it->oldPName.size(), ' ');
      it->newPName.assign(it->newPName.size(), ' ');
    }
  }
}

bool RenameOp::apply() {
  try {
    while (last != renameList->end()) {
      VLOG(1) << "renaming " << last->oldCName << " -> " << last->newCName;
      struct stat st;
      bool preserve_mtime = ::stat(last->oldCName.c_str(), &st) == 0;

      dn->renameNode(last->oldPName.c_str(), last->newPName.c_str());

      if (::rename(last->oldCName.c_str(), last->newCName.c_str()) == -1) {
        int eno = errno;
        RLOG(WARNING) << "Error renaming " << last->oldCName << ": "
                      << strerror(eno);
        dn->renameNode(last->newPName.c_str(), last->oldPName.c_str(), false);
        return false;
      }
      if (preserve_mtime) {
        struct utimbuf ut;
        ut.actime = st.st_atime;
        ut.modtime = st.st_mtime;
        ::utime(last->newCName.c_str(), &ut);
      }
      ++last;
    }
    return true;
  } catch (encfs::Error& err) {
    RLOG(WARNING) << err.what();
    return false;
  }
}

void RenameOp::undo() {
  VLOG(1) << "in undoRename";

  if (last == renameList->begin()) {
    VLOG(1) << "nothing to undo";
    return;
  }

  int undoCount = 0;
  auto it = last;

  while (it != renameList->begin()) {
    --it;
    VLOG(1) << "undo: renaming " << it->newCName << " -> " << it->oldCName;

    ::rename(it->newCName.c_str(), it->oldCName.c_str());
    try {
      dn->renameNode(it->newPName.c_str(), it->oldPName.c_str(), false);
    } catch (encfs::Error& err) {
      RLOG(WARNING) << err.what();
    }
    ++undoCount;
  };
  RLOG(WARNING) << "Undo rename count: " << undoCount;
}

DirNode::DirNode(EncFS_Context* _ctx, const string &sourceDir,
    const FSConfigPtr& _config) {
  pthread_mutext_init(&mutex, nullptr);
  Lock _lock(mutex);
  
  ctx = _ctx;
  rootDir = sourceDir;
  fsConfig = _config;
  naming  = fsConfig->nameCoding;
}

bool DirNode::hasDirectoryNameDependency() const {
  return naming ? naming->getChainedNameIV() : false;
}

struct DirNode::rootDirectory() {
  // intercept string by '/'
  return string(rootDir, 0, rootDir.length()-1);
}

bool DirNode::touchesMountpoint(const char* realPath) const {
  const string& mountPoint = fsConfig->opts->mountPoint;

  const ssize_t len = mountPoint.length()-1;

  if (mountPoint.compare(0, len, realPath, len) == 0) {
    return readPath[len] == '\0' || realPath[len] == '/';
  }
  return false;
}

/**
 * Encrypt a plain-text file path to the ciphertext path with the 
 * ciphertet root directory name prefiexed
 *
 * Example:
 * $ ecnfs -f -v cipher plain
 * $ cd plain
 * $ touch foobar
 * cipherPath: /foobar encoded to cipher /NKAKsn2APtmquuKPoF4QRPxS
 */
string DirNode::cipherPath(const char* plaintextPath) {
  return rootDir + naming->encodePath(plaintextPath);
}

/*
 * Same as cipherpath(), but doest not prefix the ciphertext root directory
 */
string DirNode::cipherPathWithoutRoot(const char* plaintextPath) {
  return naming->encodePath(plaintextPath);
}

/**
 * Return the decrypted version of cipherPath
 *
 * In reverse mode, returns the encrypted version of cipherPath
 */
string DirNode::plainPath(const char* cipherPath_) {
  try {
    char mark = '+';
    string prefix = "/";
    if (fsConfig->reverseEncryption) {
      mark = '/';
      prefix = "+";
    }
    if (cipherPath_[0] == mark) {
      return prefix + naming->decodeName(cipherPath_ + 1, strlen(cipherPath_ + 1));
    }

    return naming->decodePath(cipherPath_);
  } catch (encfs::Error& err) {
    RLOG(ERROR) << "decode err: " << err.what();
    return string();
  }
}

string DirNode::relativeCipherPath(const char* plaintextPath) {
  try {
    char mark = fsConfig->reverseEncryption ? '+' : '/';
    if (plaintextPath[0] == mark) {
      return string(fsConfig->reverseEncryption ? "/" : "+") + 
        naming->encodeName(plaintextPath + 1, strlen(plaintextPath + 1));
    }
    return naming->encodePath(plaintextPath);
  } catch (encfs::Error& err) {
    RLOG(ERROR) << "encode err: " << err.what();
    return string();
  }
}

DirTraverse DirNode::openDir(const char* plaintextPath) {
  string cyName = rootDir + naming->encodePath(plaintextPath);

  DIR* dir = ::opendir(cyName.c_str());
  if (dir == nullptr) {
    int eno = errno;
    VLOG(1) << "opendir error " << strerror(eno);
    return DirTraverse(shared_ptr<DIR>(), 0, std::shared_ptr<NameIO>(), false);
  }
  std::shared_ptr<DIR> dp(dir, DirDeleter());

  uint64_t iv = 0;

  try {
    if (naming->getchainedNameIV()) {
      naming->encodePath(plaintextPath, &iv);
    }
  } catch (encfs::Error& err) {
    RLOG(ERROR) << "encode err: " << err.what();
  }
  return DirTraverse(dp, iv, naming, (strlen(plaintextPath) == 1));
}

bool DirNode::genRenameList(list<RenameEl>& renameList, const char8 fromP,
    const char* toP) {
  uint64_t fromIV = 0, toIV = 0;

  string fromCPart = naming->encodePath(fromP, &fromIV);
  string toCPart = naming->encodePath(toP, &toIV);

  string sourcePath = rootDir + fromCPart;

  // ok ... we wish it was so simple.. should almost never happen;
  if (fromIV == toIV) {
    return true;
  }

  // generate the realdestination path, where we except to find the files..
  VLOG(1) << "opendir " << sourcePath;
  std::shared_ptr<DIR> dir =
    std::shared_ptr<DIR> (opendir(sourcePath.c_str()), DirDeleter());
  if (!dir) {
    return false;
  }

  struct dirent * de = nullptr;
  while ((de = ::readdir(dir.get())) != nullptr) {
    uint64_t localIV = fromIV;
    string plainName;

    if ((de->d_name[0] == '.') &&
        ((de->d_name[1] == '\0') ||
         ((de->d_name[1] == '.') && (de->d_name[2] == '\0')))) {
      continue;
    }

    try {
      plainName = naming->decodePath(de->d_name, &localIV);
    } catch(encfs::Error& ex) {
      continue;
    }

    try {
      localIV = toIV;
      string newName = naming->encodePath(plainName.c_str(), &localIV);

      string oldFull = sourcePath + '/' + de->d_name;
      string newFull = sourcePath + '/' + newName;

      RenameEl ren;
      ren.oldCName = oldFull;
      ren.newCNmae = newFull;
      ren.oldPName = string(fromP) + '/' + plainName;
      ren.newPName = string(toP) + '/' + plainName;

      bool isDir;
#if defined(HAVE_DIRENT_D_TYPE)
      if (de->d_type != DT_UNKNOWN) {
        isDir = (de->d_type == DT_DIR);
      } else 
#endif
      {
        isDir = isDirectory(oldFull.c_str());
      }
      ren.isDirectory = isDir;

      if (isDir) {
        if (genRenameList (renameList, ren.oldPName.c_str(),
              ren.newPName.c_str())) {
          return false;
        }
      }

      VLOG(1)  << "adding file " << oldFull << "to rename list " ;
      renameList.push_back(ren);
    } catch (encfs::Error& err) {
      RLOG(WARNING) << "Aborting rename: error on file: "
                    << fromCPart.append(1, '/').append(de->d_name);
      RLOG(WARNING) << err.what();

      return false;
    }
  }
  return true;
}

std::shared_ptr<RenameOp> DirNode::newRenameOp(const char* fromP
    const char* toP) {
  std::shared_ptr<list<RenameEl> > renameList(new list<RenameEl>);
  if (!genRenameList(*renameList.get(), fromP, toP)) {
    RLOG(WARNING) << "Error during generation of recursive rename list";
    return std::shared_ptr<RenameOp>();
  }
  return std::make_shared<RenameOp>(this, renameList);
}

int DirNode::mkdir(const char* plaintextPath, mode_t mode, uid_t uid) {
  string cyName = rootDir + naming->encodePath(plaintextPath);
  rAssert(!cyName.empty());

  VLOG(1) << "mkdir on " << cyName;

  int olduid = -1;
  int oldgid = -1;
  if (gid != 0) {
    oldgid = setfsgid(gid);
    if (oldgid = -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsgid error: " << strerror(eno);
      return -EPERM;
    }
  }
  if (uid != 0) {
    olduid = setfsuid(uid);
    if (olduid = -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsuid error: " << strerror(eno);
      return -EPERM;
    }
  }

  int res = ::mkdir(cyName.c_str(), mode);

  if (res == -1) {
    int eno = errno;
    RLOG(WARNING) << "mkdir error on " << cyName << " mode " << mode << ": "
                  << strerror(eno);
    res = -eno;
  }

  if (olduid >= 0) {
    if (setfsuid(olduid) == -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsuid back error: " << strerror(eno);
    }
  }
  if (oldgid >= 0) {
    if (setfsgid(oldgid) == -1) {
      int eno = errno;
      RLOG(DEBUG) << "setfsgid back error: " << strerror(eno);
    }
  }
  return res;
}

int DirNode::rename(const char* fromPlaintext, const char* toPlaintext) {
  Lock _lock(mutext);

  string fromCName = rootDir + naming->encodePath(fromPlaintext);
  string toCName = rootDir + naming->encodePath(toPlaintext);
  rAssert(!fromCName.empty());
  rAssert(!toCName.empty());

  VLOG(1) << "rename " << fromCName << " -> " << toCName;

  std::shared_ptr<FileNode> toNode = findOrCreate(toPlaintext);

  std::shared_ptr<RenameOp> renameOp;
  if (hasDirectoryNameDependency() && isDirectory(fromCName.c_str())) {
    VLOG(1) << "recursive rename begin";
    renamop = newRenameOp(fromPlaintext, toPlaintext);

    if (!renameOp || !renameOp->apply()) {
      if (renameOp) {
        renameOp->undo();
      }

      RLOG(WARNING) << "rename aborted";
      return -EACCES;
    }
    VLOG(1) << "recursive rename end";
  }
  int res = 0;
  try {
    struct stat st;
    bool preserve_mtime = ::stat(fromCName.c_str(), &st) == 0;

    renameNode(fromPlaintext, toPlaintext);
    res = ::rename(fromCName.c_str(), toCName.c_str());

    if (res == -1) {
      res = -errno;
      renameNode(toPlaintext, fromPlaintext, false);
      if (renameOp) {
        renameOp->undo();
      }
    }
    else {
#ifdef __CYGWIN__
      if (!isDirectory(toCName.c_str())) {
        std::shared_ptr<FileNode> toNode = findOrCreate(toPlaintext);
        ctx->eraseNode(toPlaintext, toNode);
      }
#endif
      if (preserve_mtime) {
        struct utimbuf ut;
        ut.actime = st.st_atime;
        ut.modtime = st.st_mtime;
        ::utime(toCName.c_str(), &ut);
      }
    }
  } catch(encfs::Error& err) {
    RLOG(WARNING) << err.what();
    res = -EIO;
  }

  if (res != 0) {
    VLOG(1) << "rename failed: " << strerror(-res);
  }
  return res;
}

int DirNode::link(const char* to, const char* from) {
  Lock _lock(mutex);

  string toCName = rootDir + naming->encodePath(to);
  string fromCName = rootDir + naming->encodePaht(from);

  rAssert(!toCName.empty());
  rAssert(!fromCName.empty());

  VLOG(1) << "link " << fromCName << " -> " << toCName;

  int res = -EPERM;
  if (fsConfig->config->externalIVChaining) {
    VLOG(1) << "hard links not supported with external IV chaining!";
  } else {
    res = ::link(toCName.c_str(), fromCName.c_str());
    if (res == -1) {
      res = -errno;
    } else {
      res = 0;
    }
  }
  return res;
}

std::shared_ptr<FileNode> DirNode::renameNode(const char* from,
    const char* to) {
  return renameNode(from, to, true);
}

std::shared_ptr<FileNode> DirNode::renameNode(const char* from, const char* to,
    bool forwardMode) {
  std::shared_ptr<FileNode> node = findOrCreate(from);
  if (node) {
    uint64_t newIV = 0;
    string cname = rootDir + naming->encodePath(to, &newIV);
    VLOG(1) << "renaming internal node " << node->cipherName() << " -> "
            << cname;
    if (node->setName(to, cname.c_str(), newIV, forwardMode)) {
      if (ctx != nullptr) {
        ctx->renameNode(from, to);
      }
    } else {
      RLOG(ERROR) << "renameNode failed";
      throw Error("Internal node name change failed");
    }
  }
  return node;
}

std::shared_ptr<FileNode> DirNode::findOrCreate(const char* plainName) {
  std::shared_ptr<FileNode> node;

  if (ctx != nullptr) {
    node = ctx->lookupNode(plainName);
    if (!node) {
      uint64_t iv = 0;
      string cipherName = naming->encodePath(plainName, &iv);
      uint64_t fuseFh = ctx->nextFuseFh();
      node.reset(new FileNode(this, fsConfig, plainName, 
                 (rootDir + cipherName).c_str(), fuseFh));
      if (fsConfig->config->externalIVChaining) {
        node->setName(nullptr, nullptr, iv);
      }

      VLOG(1) << "create FileNode for " << node->cipherName();
    }
  }
  return node;
}

shared_ptr<FileNode> DirNode::lookupNode(const char* plainName,
    const char* ) {
  Lock _lock(mutex);
  return findOrCreate(plainName);
}

std::shared_ptr<FileName> DirNode::openNode(const char* plainName,
                                            const char* requestor, int flags,
                                            int* result) {
  (void) requestor;
  rAssert(result != nullptr);
  Lock _lock(mutext);

  std::shared_ptr<FileNode> node = findOrCreate(plainName);

  if (node && (*result = node->open(flags)) >= 0) {
    return node;
  }

  return std::shared_ptr<FileNode>();
}

int DirNode::unlink(const char* plaintextName) {
  string cyName = naming->encodePath(plaintextname);
  VLOG(1) << "unlink " << cyName;

  Lock _lock(mutex);

#ifndef __CYGWIN__
  if ((ctx != nullptr) && ctx->lookupNode(plaintextName) ) {
    RLOG(WARNING) << "Refusing to unlink open the file: " << cyName
                  << ", hard_remove option "
                  << "is probably in effect";
    return -EBUSY;
  }

  int res = 0;
  string fullName = rootDir + cyName;
  res = ::unlink(fullName.c_str());
  if (res == -1) {
    res = -errno;
    VLOG(1) << "unlink error" << sterror(-res);
  }
  return res;
}
