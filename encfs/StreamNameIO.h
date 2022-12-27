#ifndef _StreamNameIO_incl_
#define _StreamNameIO_incl_

#include <memory>
#include <stdint.h>

#include "CipherKey.h"
#include "Interface.h"
#include "NameIO.h"

namespace encfs {
class Cipher;

class StreamNameIO : public NameIO {
public:
  static Interface CurrentInterface();

  StreamNameIO(const Interface &iface, std::shared_ptr<Cipher> cipher,
               CipherKey key);
  virtual ~StreamNameIO();

  virtual Interface interface() const;

  virtual int maxEncodedNameLen(int plaintextNameLen) const;
  virtual int maxDecodedNameLen(int encodedNameLen) const;

  // hack to help with static builds
  static bool Enabled();

protected:
  virtual int encodeName(const char *plaintextName, int length, uint64_t *iv,
                         char *encodedName, int bufferLength) const;
  virtual int decodeName(const char *encodedName, int length, uint64_t *iv,
                         char *plaintextName, int bufferLength) const;

private:
  int _interface;
  std::shared_ptr<Cipher> _cipher;
  CipherKey _key;
};

} // namespace encfs
#endif
