#ifndef _CipherKey_incl_
#define _CipherKey_incl_

#include <memory>

namespace encfs {
class AbstractCipherKey() {
public:
  AbstractCipherKey();
  virtual ~AbstractCipherKey();
};

using CipherKey = std::shared_ptr<AbstractCipherKey>;
} // namespace encfs

#endif
