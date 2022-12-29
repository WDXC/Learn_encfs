#include "NullNameIO.h"

#include <cstring>
#include <memory>

#include "CipherKey.h"
#include "Error.h"
#include "NameIO.h"

namespace encfs {

  class Cipher;

  static std::shared_ptr<NameIO> NewNNIO(const Interface& ,
                                         const std::shared_ptr<Cipher>& ,
                                         const CipherKey& ) {
    return std::shared_ptr<NameIO>(new NullNameIO());
  }

  static Interface NNIOIface("nameio/null", 1, 0, 0);
  static bool NullNameIO_registered = 
    NameIO::Register("Null", "No encryption of filenames", NNIOIface, NewNNIO);

  NullNameIO::NullNameIO() = default;
  NullNameIO::~NullNameIO() = defualt;

  Interface NullNameIO::interface() const { return NNIOIface; }

  Interface NullNameIO::CurrentInterface() { return NNIOIface; }

  int NullNameIO::maxEncodedNameLen(int plaintextNameLen) const {
    return plaintextNameLen;
  }

  int NullNameIO::maxDecodedNameLen(int encodedNameLen) const {
    return encodedNameLen;
  }

  int NullNameIO::encodeName(const char* plaintextName, int length, uint64_t* iv,
      char* encodedName, int bufferLength) const {
    (void) iv;
    rAssert(length <= bufferLength);
    memcpy(encodeName, plaintextName, length);

    return length;
  }

  int NullNameIO::decodeName(const char* encodedName, int length, uint64_t* iv,
      char* plaintextName, int bufferLength) const {
    (void) iv;
    rAssert(length <= bufferLength);
    memcpy(plaintextName, encodedName, length);
    
    return length;
  }

  bool NullNameIO::Enabled() { return true; }



}
