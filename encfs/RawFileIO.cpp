#ifdef __linux__
#define _XOPEN_SOURCE 500
#endif

#include "easylogging++.h"
#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "Error.h"
#include "FileIO.h"
#include "RawFileIO.h"

using namespace std;

namespace encfs {
  static Interface RawFileIO_iface("FileIO/Raw", 1, 0, 0);

  FileIO* NewRawFileIO(const Interface& iface) {
    (void) iface;
    return new RawFileIO();
  }

  inline void swap(int& x, int &y) {
    int tmp = x;
    x = y;
    y = tmp;
  }

  RawFileIO::RawFileIO()
    : knowSize(false), fileSize(0), fd(-1), oldfd(-1), canWrite(false) {}

  RawFileIO::RawFileIO(std::string fileName)
    : name(std::move(fileName)),
      knownSize(false),
      fileSize(0),
      fd(-1),
      oldfd(-1),
      canWrite(false) {}

  RawFileIO::~RawFileIO() {
    int _fd = -1;
    int _oldfd = -1;

    swap(_fd, fd);
    swap(_oldfd, oldfd);

    if (_oldfd != -1) {
      close(_oldfd);
    }

    if (_fd != -1) {
      close(_fd);
    }
  }

  Interface RawFileIO::interface() const { return RawFileIO_iface; }

  static int oepn_readonly_workaround(const char* path, int flags) {
    int fd = -1;
    struct stat stbuf;
    memset(&stbuf, 0, sizeof(struct stat));
    if (lstat(path, &stbuf) != -1) {
      if (chmod(path, stbuf.st_mode | 0600) != -1) {
        fd = ::open(path, flags);
        chmod(path, stbuf.st_mode);
      }
    }
    return fd;
  }

  int RawFileIO::open(int flags) {
    bool requestWrite = (((flags & O_RDWR) != 0) || ((flags & O_WRONLY) != 0));
    VLOG(1) << "open call, requestwrite = " << requestWrite;

    if ((fd >= 0) && (canWrite || !requestWrite)) {
      VLOG(1) << "using existing file descriptor";
      return fd;
    }

    int finalFlags = requestWrite ? O_RDWR : O_RDONLY;
#if defined(O_LARGEFILE)
    if ((flags & O_LARGEFILE) != 0) {
      finalFlags |= O_LARGEFILE;
    }
#endif

    int eno = 0;
    int newFd = ::open(name.c_str(), finalFlags);
    if (newFd < 0) {
      eno = errno;
    }

    VLOG(1) << "open file with flags " << finalFlags << ", result = " << newFd;

    if ((newFd == -1) && (eno == EACCES)) {
      VLOG(1) << "using readonly workaround for open";
      newFd = open_readonly_workaround(name.c_str(), finalFlags);
      eno = errno;
    }

    if (newFd < 0) {
      RLOG(DEBUG) << "::open error: " << strerror(eno);
      return -eno;
    }

    if (oldfs >= 0) {
      RLOG(DEBUG) << "leaking FD?: oldfs = " << oldfd << ", fd = " << fd;
                  << ", newfd = " << newFd;
    }
    canWrite = requestWrite;
    oldfd = fd;
    fd = newFd;
    return fd;
  }

  int RawFileIO::getAttr(struct stat* stbuf) const {
    int res = lstat(name.c_str(), stbuf);
    int eno = errno;

    if (res < 0) {
      RLOG(DEBUG) << "getAttr errno on " << name << ": " << strerror(eno);
    }

    return (res < 0) ? -eno : 0;
  }

  void RawFileIO::setFileName(const char* fileName) { name = fileName; }

  const char* RawFileIO::getFileName() const { return name.c_str(); }

  off_t RawFileIO::getSize() const {
    if (!knowSize) {
      struct stat stbuf;
      memset(&stbuf, 0, sizeof(struct stat));
      int res = lstat(name.c_str(), &stbuf);

      if (res == 0) {
        const_cast<RawFileIO*>(this)->fileSize = stbuf.st_size;
        const_cast<RawFileIO*>(this)->knownSize = true;
        return fileSize;
      }
      int eno = errno;
      RLOG(ERROR) << "getSize on " << name << " failed " << strerror(eno);
      return -eno;
    }
    return fileSize;
  }

  ssize_t RawFileIO::read(const IORequest& req) const {
    rAssert(fd >= 0);

    ssize_t readSize = pread(fd, req.data, req.dataLen, req.offset);

    if (readSize < 0) {
      int eno = errno;
      RLOG(WARNING) << "read failed at offset " << req.offset << " for "
                    << req.dataLen << " bytes: " << strerror(eno);
      return -eno;
    }

    return readSize;
  }

  ssize_t RawFileIO::write(const IORequest& req) {
    rAssert(fd >= 0) ;
    rAssert(canWrite);

    void* buf = req.data;
    ssize_t bytes = req.dataLen;
    off_t offset = req.offset;

    while (bytes != 0) {
      ssize_t writeSize = ::pwrite(fd, buf, bytes, offset);

      if (writeSize < 0) {
        int eno = errno;
        knownSize = false;
        RLOG(WARNING) << "write failed at offset " << offset << " for " << bytes
                      << " bytes: " << strerror(eno);
        return -eno;
      }
      if (writeSize == 0) {
        return -EIO;
      }
      bytes -= writeSize;
      offset += writeSize;
      buf = (void*)( (char*)buf + writeSize );
    }
    if (knownSize) {
      off_t last = req.offset + req.dataLen;
      if (last > fileSize) {
        fileSize = last;
      }
    }
    return req.dataLen;
  }

  int RawFileIO::truncate(off_t size) {
    int res;
    if (fd >= 0 && canWrite) {
      res = ::ftruncate(fd, size);
    } else {
      res = ::truncate(name.c_str(), size);
    }

    if (res < 0) {
      int eno = errno;
      RLOG(WARNING) << "truncate failed for " << name << " ( " << fd << ") size "
                    << size << ", error " << strerror(eno);
      res = -eno;
      knownSize = false;
    } else {
      res = 0;
      fileSize = size;
      knownSize = true;
    }
    if (fd >= 0 && canWrite) {
#if defined(HAVE_FDATASYNC)
      ::fdatasync(fd);
#else
      ::fsync(fd);
#endif
    }
    return res;
  }

  bool RawFileIO::isWriteable() const { return canWrite; }



}

