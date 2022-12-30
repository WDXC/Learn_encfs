#include "CipherFileIO.h"

#include "easylogging++.h"
#include <cerrno>
#include <cinttypes>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <utility>

#include "BlockFileIO.h"
#include "Cipher.h"
#include "CipherKey.h"
#include "Error.h"
#include "FileIO.h"

namespace encfs {

static Interface CipherFileIO_iface("FileIO/Cipher", 2, 0, 1);

const int HEADER_SIZE = 8;

CipherFileIO::CipherFileIO(std::shared_ptr<FileIO> _base,
                           const FSconfigPtr& cfg)
  : BlockFileIO(cfg->config->blockSize, cfg),
    base(std::move(_base)),
    haveHeader(cfg->config->uniqueIV),
    externalIV(0),
    fileIV(0),
    lastFlags(0) {
  fsConfig = cfg;
  cipher = cfg->cipher;
  key = cfg->key;

  CHECK_EQ(fsConfig->config->blockSize % fsConfig->cipher->cipherBlockSize(), 0)
      << "FS block size must be multiple of cipher block size";
}

CipherFileIO::~CipherFileIO() = default;

Interface CipherFileIO::interface () const { return CipherFileIO_iface; }

int CipherFileIO::open(int flags) {
  int res = base->open(flags);
  if (res >= 0) {
    lastFlags = flags;
  }

  return res;
}

void CipherFileIO::setFileName (const char* fileName) {
  base->setFileName(fileName);
}

const char* CipherFileIO::getFileName() const { return base->getFileName(); }

bool CipherFileIO::setIV(uint64_t iv) {
  VLOG(1) << "in setIV, current IV = " << externalIV << ", new IV = " << iv
          << ", fileIV = " << fileIV;
  if (externalIV == 0) {
    externalIV = iv;
    if (fileIV != 0) {
      RLOG(WARNING) << "fileIV initialized before externalIV: " << fileIV
                    << ", " << externalIV;
    }
  } else if (haveHeader) {
    int newFlags = lastFlags | O_RDWR;
    int res = base->open(newFlags);
    if (res < 0) {
      if (res == -EISDIR) {
        externalIV = iv;
        return base->setIV(iv);
      }
      VLOG(1) << "setIV failed to re-open for write";
      return false;
    }
    if (fileIV == 0) {
      if (initHeader() < 0) {
        return false;
      }
    }
    uint64_t oldIV = externalIV;
    externalIV = iv;
    if (!writeHeader()) {
      externalIV = oldIV;
      return false;
    }
  } 
  return base->setIV(iv);
}

int CipherFileIO::getAttr(struct stat* stbuf) const {
  int res = base->getAttr(stbuf);

  if ((res == 0) && haveHeader && S_ISREG(stbuf->st_mode) &&
      (stbuf->st_size > 0)) {
    if (!fsConfig->reverseEncryption) {
      rAssert(stbuf->st_size >= HEADER_SIZE);
      stbuf->st_size -= HEADER_SIZE;
    } else {
      stbuf->st_size += HEADER_SIZE;
    }
  }
  return res;
}

off_t CipherFileIO::getSize() const {
  off_t size = base->getSize();

  if (haveHeader && size > 0) {
    if (!fsConfig->reverseEncryption) {
      rAssert(size >= HEADER_SIZE);
      size -= HEADER_SIZE;
    } else {
      size += HEADER_SIZE;
    }
  }
  return size;
}

int CipherFileIO::initHeader() {
  off_t rawSize = base->getSize();
  if (rawSize >= HEADER_SIZE) {
    VLOG(1) << "reading existing header, rawSize = " << rawSize;
    
    unsigned char buf[8] = {0};

    IORequest req;
    req.offset =0;
    req.data = buf;
    req.dataLen = 8;
    ssize_t readSize = base->read(req);
    if (readSize < 0) {
      return readSize;
    }
    
    if (!cipher->streamDecode(buf, sizeof(buf), externalIV, key)) {
      return -EBADMSG;
    }

    fileIV = 0;
    for (int i = 0; i < 8; ++i) {
      fileIV = (fileIV << 8) | (int64_t) buf[i];
    }

    rAssert(fileIV != 0);
  } else {
    VLOG(1) << "creating new file IV header";
    
    unsigned char buf[8] = {0};
    do {
      if (!cipher->randomize(buf, 8, false)) {
        RLOG(ERROR) << "Unable to generate a random file IV";
        return -EBADMSG;
      }

      fileIV = 0;
      for (int i = 0; i < 8; ++i) {
        fileIV = (fileIV << 8) | (uint64_t)buf[i];
      }

      if (fileIV == 0) {
        RLOG(WARNING) << "Unexpected result: randomize returned 8 null bytes";
      }
    } while (fileIV == 0);

    if (base->isWritable()) {
      if (!cipher->streamEncode(buf, sizeof(buf), externalIV, key)) {
        return -EBADMSG;
      }

      IORequest req;
      req.offset = 0;
      req.data = buf;
      req.dataLen = 8;

      ssize_t writeSize = base->write(req);
      if (writeSize < 0) {
        return writeSize;
      }
    } else {
      VLOG(1) << "base not writable, IV not written.. ";
    }
  }
  VLOG(1) << "initHeader finished, fileIV = " << fileIV;
  return 0;
}

bool CipherFileIO::writeHeader() {
  if (fileIV == 0) {
    RLOG(ERROR) << "Internal error: fileIV == 0 in writeHeader! !!";
  }

  VLOG(1) << "writing fileIV " << fileIV;

  unsigned char buf[8] = {0};
  for (int i = 0; i < 8; ++i) {
    buf[sizeof(buf)-1-i] = (unsigned char)(fileIV & 0xff);
    fileIV >>= 8;
  }
  if (!cipher->streamEncode(buf, sizeof(buf), externalIV, key)) {
    return false;
  }

  IORequest req;
  req.offset = 0;
  req.data = buf;
  req.dataLen = 8;

  return (base->write(req) >= 0);
}

int CipherFileIO::generateReverseHeader(unsigned char* headerBuf) {
  struct stat stbuf;
  int res = getAttr(&stbuf);
  rAssert(res == 0);
  ino_t ino = stbuf.st_ino;
  rAssert(ino != 0);

  VLOG(1) << "generating reverse file IV header from ino = " << ino;

  unsigned char inoBuf[sizeof(ino_t)];

  for (unsigned int i = 0; i < sizeof(ino_t); ++i) {
    inoBuf[i] = (unsigned char) (ino & 0xff);
    ino >>= 8;
  }

  unsigned char md[20];
  SHA1(inoBuf, sizeof(ino), md);
  rAssert(HEADER_SIZE <= 20);
  memcpy(headerBuf, md, HEADER_SIZE);

  fileIV = 0;
  for (int i = 0; i < HEADER_SIZE; ++i) {
    fileIV = (fileIV << 8) | (uint64_t)headerBuf[i];
  }

  VLOG(1) << "fileIV=" << fileIV;

  if (!cipher->streamEncode(headerBuf, HEADER_SIZE, externalIV, key)) {
    return -EBADMSG;
  }
  return 0;
}

ssize_t CipherFileIO::readOneBlock(const IORequest& req) const {
  int bs = blockSize();
  off_t blockNum = req.offset / bs;

  IORequest tmpReq = req;

  if (haveHeader && !fsConfig->reverseEncryption) {
    tmpReq.offset += HEADER_SIZE;
  }

  ssize_t readSize = base->read(tmpReq);

  bool ok;
  if (readSize > 0) {
    if (haveHeader && fileIV == 0) {
      int res = const_cast<CipherFileIO*>(this)->initHeader();
      if (res < 0) {
        return res;
      }
    }
    if (readSize != bs) {
      VLOG(1) << "streamRead(data," << readSize << ", IV)";
      ok = streamRead(tmpReq,data, (int)readSize,
                      blockNum ^ fileIV);
    } else {
      ok = blockRead(tmpReq.data, (int)readSize,
                     blockNum ^ fileIV);
    }
    if (!ok) {
      VLOG(1) << "decodeBlock failed for block " << blockNum << ", size "
              << readSize;
      readSize = -EBADMSG;
    }
  } else if (readSize == 0) {
    VLOG(1) << "readSize zero for offset " << req.offset;
  }

  return readSize;
}

ssize_t CipherFileIO::writeOneBlock(const IORequest& req) {
  if (haveHeader && fsConfig->reverseEncryption) {
    VLOG(1) << "writing to a reverse mount with per-file IVs is not implemented";
    return -EPERM;
  }

  unsigned int bs = blockSize();

  off_t blockNum = req.offset / bs;

  if (haveHeader && fileIV == 0) {
    int res = initHeader();
    if (res < 0) {
      return res;
    }
  }
  bool ok;
  if (req.dataLen != bs) {
    ok = streamWrite(req.data, (int)req.dataLen,
                     blockNum ^ fileIV);
  } else {
    ok = blockWrite(req.data, (int)req.dataLen,
        blockNum ^ fileIV);
  }

  ssize_t res = 0;
  if (ok) {
    if (haveHeader) {
      IORequest tmpReq = req;
      tmpReq.offset += HEADER_SIZE;
      res = base->write(tmpReq);
    } else {
      res = base->write(req);
    }
  } else {
    VLOG(1) << "encodeBlock failed for block " << blockNum << ", size " 
            << req.dataLen;
    res = -EBADMSG;
  }
  return res;
}

bool CipherFileIO::blockWrite(unsigned char* buf, int size,
    uint64_t _iv64) const {
  VLOG(1) << "called blockWrite";
  if (!fsConfig->reverseEncryption) {
    return cipher->blockEncode(buf, size, _iv64, key);
  }
  return cipher->blockDecode(buf, size, _iv64, key);
}

bool CipherFileIO::streamWrite(unsigned char* buf, int size,
    uint64_t _iv64) const {
  VLOG(1) << "Called streamWrite";
  if (!fsConfig->reverseEncryption) {
    return cipher->streamEncode(buf, size, _iv64, key);
  }
  return cipher->streamDecode(buf, size, _iv64, key);
}

bool CipherFileIO::blockRead(unsigned char* buf, int size,
    uint64_t _iv64) const {
  if (fsConfig->reverseEncryption) {
    return cipher->blockEncode(buf, size, _iv64, key);
  }
  if (_allowHoles) {
    for (int i = 0; i < size; ++i) {
      if (buf[i] != 0) {
        return cipher->blockDeode(buf, size, _iv64, key);
      }
    }
    return true;
  }
  return cipher->blockDecode(buf, size, _iv64, key);
}

bool CipherFileIO::streamRead(unsigned char* buf, int size,
    uint64_t _iv64) const {
  if (fsConfig->reverseEncryption) {
    return cipher->streamEncode(buf, size, _iv64, key);
  }
}







}
