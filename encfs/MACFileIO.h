#ifndef _MACFileIO_incl_
#define _MACFileIO_incl_

#include <memory>
#include <stdint.h>
#include <sys/types.h>

#include "BlockFileIO.h"
#include "Cipher.h"
#include "CipherKey.h"
#include "FSConfig.h"
#include "Interface.h"

namespace encfs {
class Cipher;
class FileIO;
struct IORequest;

class MACFileIO : public BlockFileIO {
public:
  /*
      if warnOnlymode is enabled, then a MAC comparison failure will only
      result in a warning message from encfs -- the garbled data will still
      be made available..
   */
  MACFileIO(std::shared_ptr<FileIO> base, const FSConfigPtr &cfg);
  MACFileIO();

  virtual ~MACFileIO();

  virtual Interface interface() const;

  virtual void setFileName(const char *fileName);
  virtual const char *getFileName() const;
  virtual bool setIV(uint64_t iv);

  virtual int open(int flags);
  virtual int getAttr(struct stat *stbuf) const;
  virtual off_t getSize() const;

  virtual int truncate(off_t size);

  virtual bool isWritable() const;

private:
  virtual ssize_t readOneBlock(const IORequest &req) const;
  virtual ssize_t writeOneBlock(const IORequest &req);

  std::shared_ptr<FileIO> base;
  std::shared_ptr<Cipher> cipher;
  CipherKey key;
  int macBytes;
  int randBytes;
  bool warnOnly;
};
} // namespace encfs

#endif
