#include "MACFileIO.h"

#include "easylogging++.h"
#include <cinttypes>
#include <cstring>
#include <sys/stat.h>
#include <utility> 

#include "BlockNameIO.h"
#include "Cipher.h"
#include "Error.h"
#include "FileIO.h"
#include "FileUtils.h"
#include "FileUtils.h"
#include "MemoryPool.h"
#include "i18n.h"

using namespace std;

static Interface MACFileIO_iface("FileIO/MAC", 2, 1, 0);

int dataBlockSize(const FSConfigPtr& cfg) {
  return cfg->config->blockSize - cfg->config->blockMACBytes - 
         cfg->config->blockMACRandBytes;
}

MACFileIO::MACFileIO(std::shared_ptr<FileIO> _base, const FSConfigPtr& cfg)
  : BlockFileIO(dataBlockSize(cfg), cfg),
    base(std::move(_base)),
    cipher(cfg->cipher),
    key(cfg->key),
    macBytes(cfg->config->blockMACBytes),
    randBytes(cfg->config->blockMACRandBytes),
    warnOnly(cfg->opts->forceDecode) {
      rAssert(macBytes >= 0 && macBytes <= 8);
      rAssert(randBytes >= 0);
      VLOG(1) << "fs block size = " << cfg->config->blockSize
              << ", macBytes = " << cfg->config->blockMACBytes
              << ", randBytes = " << cfg->config->blockMACRandBytes;
    }

MACFileIO::~MACFileIO() = default;

Interface MACFileIO::interface() const { return MACFileIO_iface; }

int MACFileIO::open(int flags) { return base->open(flags); }

void MACFileIo::setFileName(const char* fileName) {
  base->setFileName(fileName);
}

const char* MACFileIO::getFileName() const { return base->getFileName(); }

bool MACFileIO::setIV(uint64_t iv) { return base->setIV(iv); }

inline static off_t roundUpdivide(off_t numerator, int denominator) {
  return (numerator + denominator - 1) / denominator;
}

static off_t locWithHeader(off_t offset, int blockSize, int headerSize) {
  off_t blockNum = roundUpDivide(offset, blockSize - headerSize);
  return offset + blockNum * headerSize;
}

static off_t locWithoutHeader(off_t offset, int blockSize, int headerSize) {
  off_t blockNum = roundUpDivide(offset, blockSize);
  return offset - blockNum * headerSize;
}

int MACFileIO::getAttr(struct stat* stbuf) const {
  int res = base->getAttr(stbuf);

  if (res == 0 && S_ISREG(stbuf->st_mode)) {
    int headerSize = macbytes + randBytes;
    int bs = blockSize() + headerSize;
    stbuf->st_size = locWithoutHeader(stbuf->st_size, bs, headerSize);
  }
  return res;
}

off_t MACFileIO::getSize() const {
  int headerSize = macBytes + randBytes;
  int bs = blockSize() + headerSize;

  off_t size = base->getSize();

  if (size > 0) {
    size = locWith
  }
}
