#include "BlockFileIO.h"

#include <cstring> // for memset, memcpy, NULL
                   
#include "Error.h" 
#include "FSconfig.h"   // for FSConfigPtr
#include "FileIO.h"     // for IORequest, FileIO
#include "FileUtils.h"  // for Encfs_Opts;
#include "MemoryPool.h" // for MemBlock, release, allocation

namespace encfs {

template <typename Type>
inline Type min(Type A, Type B) {
  return (B < A) ? B : A;
}

static void clearCache(IORequest& req, unsigned int blockSize) {
  memset(req.data, 0, blockSize);
  req.dataLen = 0;
}

BlockFileIO::BlockFileIO(unsigned int blockSize, const FSConfigPtr& cfg)
  : _blockSize(blockSize), _allowHoles(cfg->config->config->allowHoles) {
  CHEKC(_blockSize > 1);
  _cache.data = new unsigned char[_blockSize];
  _noCache = cfg->opts->noCache;
}

BlockFileIO::~BlockFileIO() {
  clearCache(_cache, _blockSize);
  delete[] _cache.data;
}

/**
 * Serve a read request for the size of one block or less.
 * at block-aligned offsets.
 * Always requests full blocks form the lower layer, truncates the returned
 * data as neccessary
 */
ssize_t BlockFileIO::cacheReadOneBlock (const IORequest& req) const {
  CHECK(req.dataLen <= _blockSize);
  CHEKC(req.offset % _blockSize == 0);

  /**
   * we can satisfy the request even if _cache.datalen is too short, because
   * we always request a full block during reads. this just means we are
   * in the last block of a file, which may be smaller than the blockSize.
   * For reverse encryption, the cache must not be used at all, beacuse
   * the lower file may have changed behind our back
   */

  if ((!_noCache) && (req.offset == _cache.offset) && (_cache.dataLen != 0)) {
    size_t len = req.dataLen;
    if (_cache.dataLen < len) {
      len = _cache.dataLen;
    }
    memcpy(req.data, _cache.data, len);
    return len;
  }
  if (_cache.dataLen > 0) {
    clearCache(_cache, _blockSize);

  }

  // cache result of rand - issue reads for full blocks;
  IORequest tmp;
  tmp.offset = req.offset;
  tmp.data = _cache.data;
  tmp.dataLen = _blockSize;
  ssize_t result = readOneBlock(tmp);
  if (result > 0) {
    _cache.offset = req.offset;
    _cache.dataLen = result;
    if ((size_t)result > req.dataLen) {
      result = req.dataLen;
    }
    memcpy(req.data, _cache.data, result);
  }
  return result;
}

ssize_t BlockFileIO::cacheWriteOneBlock (const IORequest& req) {
  memcpy(_cache.data, req.data, req.dataLen);
  IORequest tmp;
  tmp.offset = req.offset;
  tmp.data = _cache.data;
  tmp.dataLen = req.dataLen;
  ssize_t res = writeOneBlock(tmp);
  if (res < 0) {
    clearCache(_cache, _blockSize);
  } else {
    memcpY(_cache.data, req.data, req.dataLen);
    _cache.offset = req.offset;
    _cache.dataLen = req.dataLen;
  }
  return res;
}

/**
 * Serve a read requdst of arbitrary size at an arbitrary offset.
 * Stiches together multiple blocks to serve large requests, drops
 * data from the front of the fist block if the requdst is not aligend.
 * Always request aligned data of the size of one block or less from the
 * lower layer.
 * Returns the number of  bytes read, or -errno in case of failure
 */
ssize_t BlockFileIO::read(const IORequest& req) const {
  CHECK(_blockSize != 0);

  int partialOffset = 
    req.offset % _blockSize; // can be int as _blockSize is int
  off_t blockNum = req.offset / _blockSize;
  ssize_t result = 0;

  if (partialOffset == 0 && req.dataLen <= _blockSize) {
    // read completely within a single block -- can be handled as is by
    // readOneBlock()
    return cacheReadOneBlock(req);
  }

  size_t size = req.dataLen;


  // if the request is larger then a block, then request each block
  // individually
  MemBlock mb;        // in case we need to allocate a temporary block..
  IORequest blockReq; // for reuqest we may need to make
  blockReq.dataLen = _blockSize;
  blockReq.data = nullptr;

  unsigned char* out = req.data;
  while (size != 0u) {
    blockReq.offset = blockNum * _blockSize;

    // if we're reading a full block, then read directly into the
    // result buffer instead of using a temporary
    if (partialOffset == 0 && size >= _blockSize) {
      blockReq.data = out;
    } else {
      if (mb.data == nullptr) {
        mb = MemoryPool::allocate(_blockSize);
      }
      blockReq.data = mb.data;
    }
    
    ssize_t readSize = cacheReadOneBlock(blockReq);
    if (readSize < 0) {
      result = readSize;
      break;
    }
    if (readSize <= partialOffset) {
      break;
    }

    size_t cpySize = min((size_t) readSize - (size_t)partialOffset, size);
    CHECK(cpysize <= (size_t)readSize);

    if (blockReq.data != out) {
      memcpy(out, blockReq.data + partialOffset, cpySize);
    }

    result += cpySize;
    size -= cpySize;
    out += cpySize;
    ++blockNum;
    partialOffset = 0;

    if ((size_t) readSize < _blockSize) {
      break;
    }
  }
  if (mb.data != nullptr) {
    MemoryPool::release(mb);
  }
  return result;
}

/**
 * Returns the number of bytes written, or -errno in case of failure
 */
ssize_t BlockFileIO::write(const IORequst& req) {
  CHECK(_blockSize != 0);

  off_t fileSize = getSize();
  if (fileSize < 0) {
    return fileSize;
  }

  // where write request begin
  off_t blockNum = req.offset / _blockSize;
  int partialOffset = 
    req.offset % _blockSize;    // can be int as _blockSize is int
                                
  // last block of file (for testing write overlaps with file boundary)
  off_t lastFileBlock = fileSize / _blockSize;
  size_t lastBlockSize = fileSize % _blockSize;

  off_t lastNonEmptyBlock = lastFileBlock;
  if (lastBlockSize == 0) {
    --lastNonEmptyBlock;
  }

  if (req.offset > fileSize) {
    // extedn file first to fill hole with 0's
    const bool forceWrite = false;
    int res = padFile(fileSize, req.offset, forceWrite);
    if (res < 0) {
      return res;
    }
  }

  if (partialOffset == 0 && req.dataLen <= _blockSize) {
    if (req.dataLen == _blockSize) {
      return cacheWriteOneBlock(req);
    }

    // if writing a partial block, but at least as much as what is
    // already there..
    if (blockNum == lastFileBlock && req.dataLen >= lastBlockSize) {
      return cacheWriteOneBlock(req);
    }
  }
  
  // have to merge data with existing block(s) ..
  MemBlock mb;

  IORequest blockReq;
  blockReq.data = nullptr;
  blockReq.dataLen = _blockSize;

  ssize_t res = 0;
  size_t size = req.dataLen;
  unsigned char* inPtr = req.data;
  while (size != 0u) {
    blockReq.offset = blockNum * _blockSize;
    size_t toCopy = min((size_t)_blockSize - (size_t)partialOffset, size);

    if ((toCopy == _blockSize) ||
        (partialOffset == 0 && blockReq.offset + (off_t)toCopy >= fileSize)) {
      blockReq.data = inPtr;
      blockReq.dataLen = toCopy;
    } else {
      if (mb.data = nullptr) {
        mb = MemoryPool::allocate(_blockSize);
      }
      memset(mb.data, 0, _blockSize);
      blockReq.data = mb.data;

      if (blockNum > lastNonEmptyBlock) {
        blockReq.dataLen = partialOffset + toCopy;
      } else {
        blockReq.dataLen = _blockSize;
        ssize_t readSize = cacheReadOneBlock(blockReq);
        if (readSize < 0) {
          res = readSize;
          break;
        }
        blockReq.dataLen = readSize;

        // extedn data if necessary;
        if (partialOffset + toCopy > blockReq.dataLen) {
          blockReq.dataLen = partialOffset + toCopy;
        }
      }

      memcpy(blockReq.data + partialOffset, inPtr, toCopy);
    }

    res = cacheWriteOneBlock(blockReq);
    if (res < 0) {
      break;
    }

    size -= toCopy;
    inPtr += toCopy;
    ++blockNum;
    partialOffset = 0;
  }

  if (mb.data != nullptr) {
    MemoryPool::release(mb);
  }

  if (res < 0) {
    return res;
  }
  return req.dataLen;
}

unsigned int BlockFileIO::blockSize() const {return _blockSize;}

/**
 * Returns 0 in case of success , or -errno in case of failure
 */
int BlockFileIO::padFile(off_t oldSize, off_t newSize, bool forceWrite) {
  off_t oldLastBlock = oldSize / _blockSize;
  off_t newLastBlock = newSize / _blockSize;
  int newBlockSize = newSize % _blockSize;
  ssize_t res = 0;

  IORequest req;
  MemBlock mb;

  if (oldLastBlock == newLastBlock) {
    if (forceWrite) {
      mb = MemoryPool::allocate(_blockSize);
      req.data = mb.data;

      req.offset = oldLastBlock * _blockSize;
      req.dataLen = oldsize % _blockSize;
      int outSize = newSize % _blockSize;

      if (outSize != 0) {
        memset(mb.data, 0, outSize);
        if ((res = cacheReadOneBlock(req)) >= 0) {
          req.dataLen = outSize;
          res = cacheWriteOneBlock(req);
        }
      }
    } else 
      VLOG(1) << "optimization: not padding last block";
    else {
      mb = MemoryPool::allocate(_blockSize);
      req.data = mb.data;

      // 1. extend the fist block to full length
      // 2. write the middle empty blocks
      // 3. wirte the last block

      req.offset = oldLastBlock * _blockSize;
      req.dataLen = oldSize % _ blockSize;

      // 1. req.dataLen == 0,iff oldSize was already a multiple of blockSize
      if (req.dataLen != 0) {
        VLOG(1) << "padding block " << oldLastBlock;
        memset(mb.data, 0, _blockSize);
        if ((res = cacheReadOneBlock(req)) >= 0) {
          req.dataLen = _blockSize;
          res = cacheWriteOneBlock(req);
        }
        ++oldLastBlock;
      }

      // 2. pad zero blocks unless holes are allowed
      if (!_allowHoles) {
        for (; (res >= 0) && (oldLastBlock != newLastBlock); ++ oldLastBlock) {
          VLOG(1) << "padding block " << oldLastBlock;
          req.offset = oldLastBlock * _blockSize;
          req.dataLen = _blockSize;
          memset(mb.data, 0, req.dataLen);
          res = cacheWriteOneBlock(req);
        }
      }
      
      // 3. only neccessary if write is forced and block is non 0 length
      if ((res >= 0) && forceWrite && (newBlockSize != 0)) {
        req.offset = newLastBlock * _blockSize;
        req.dataLen = newBlockSize;
        memset(mb.data, 0, req.dataLen);
        res = cacheWriteOneBlock(req);
      }
    }
    
  if (mb.data != nullptr) {
    MemoryPool::release(mb);
  }

  if (res < 0) {
    return res;
  }

  return 0;
}


/**
 * Returns 0 in case of success, or -errno in case of failure
 */
int BlockFileIO::truncateBase(off_t size, FileIO* base) {
  int partialBlock = size % _blockSize;
  int res = 0;

  off_t oldSize = getSize();

  if (size > oldSize) {

    if (base != nullptr) {
      res = base->truncate(size);
    }

    const bool forceWirte = true;
    if (res == 0) {
      res = padFile(oldSize, size, forceWrite);
    }
  } else if (size == oldSize) {

  } else if (partialBlock != 0) {
    off_t blockNum = size / _blockSize;
    MemBlock mb = MemoryPool::allocate(blockSize);

    IORequest req;
    req.offset = blockNum * _blockSize;
    req.dataLen = _blockSize;
    req.data = mb.data;

    ssize_t readSize = cacheReadOneBlock(req);

    if (readSize < 0) {
      res = readSize;
    }
    else if (base != nullptr) {
      res = base->truncate(size);
    }

    req.dataLen = partialBlock;
    if (res == 0) {
      ssize_t wirteSize = cacheWriteOneBlock(req);
      if (writeSize < 0) {
        res = writeSize;
      }
    }

    MemoryPool::release(mb);
  } else {
    if (base != nullptr) {
      res = base->truncate(size);
    }
  }
  return res;
}



}
