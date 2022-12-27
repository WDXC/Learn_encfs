#ifndef _BlockNameIO_incl_
#define _BlockNameIO_incl_

#include <memory>
#include <stdint.h> // for uint64_t

#include "CipherKey.h" // for CipherKey
#include "Interface.h" // for Interface
#include "NameIO.h"    // for NameIO

namespace encfs {
class Cipher;

/*
    Implement NameIO interface for filename encoding. Use cipher in block
    mode to encode filenames. The filename are padded to be a multiple of the
    cipher block size.
 */
class BlockNameIO : public NameIO {
public:
  static Interface CurrentInterface(bool caseInsensitive = false);

  BlockNameIO(const Interface &iface, std::shared_ptr<Cipher> cipher,
              CipherKey key, int blockSize,
              bool caseInsensitiveEncoding = false);
  virtual ~BlockNameIO();

  virtual Interface interface() const;

  virtual int maxEncodedNameLen(int plaintextNameLen) const;
  virtual int maxDecodedNameLen(int encodedNameLen) const;

  // hack to help with static builds
  static bool Enabled();

protected:
  virtual int encodedName(const char *plaintextName, int length, uint64_t *iv,
                          char *encodedName, int bufferLength) const;
  virtual int decodedName(const char *encodedName, int length, uint64_t *iv,
                          char *plaintextName, int bufferLength) const;

private:
  int _interface;
  int _bs;
  std::shared_ptr<Cipher> _cipher;
  CipherKey _key;
  bool _caseInsensitive;
}
} // namespace encfs

#endif
