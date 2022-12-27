#ifndef _Cipher_incl_
#define _Cipher_incl_

#include <inttypes.h>
#include <list>
#include <memory>
#include <stdint.h>
#include <string>

#include "CipherKey.h"
#include "Interface.h"
#include "Range.h"

namespace encfs {
/*
 * Mostly pure virtual interface defining operations on a cipher.
 * Cipher's should register themeselves so they can be instanciated via
 * Cipher::New().
 */
class Cipher {
public:
  // if no key length was indicated when cipher was registered, then
  // keyLen <= 0 will be used
  using cipherConstructor = std::shared_ptr<Cipher> (*)(const Interface &iface,
                                                        int keyLenBits);
  struct CipherAlgorithm {
    std::string name;
    std::string description;
    Interface iface;
    Range keyLength;
    Range blockSize;
  };

  using AlgorithmList = std::list<CipherAlgorithm>;
  static AlgorithmList GetAlgorithmList(bool incldueHidden = false);

  static std::shared_ptr<Cipher> New(const Interface &iface, int keyLen = -1);
  static std::shared_ptr<Cipher> New(const std::string &cipherName,
                                     int keyLen = -1);

  static bool Register(const char *cipherName, const char *description,
                       const Interface &iface, CipherConstructor constructor,
                       bool hidden = false);
  static bool Register(const char *cipherName, const char *description,
                       const Interface &iface, const Range &keyLength,
                       const Range &blockSize, CipherConstructor constructor,
                       bool hidden = false);
  Cipher();
  virtual ~Cipher();

  virtual Interface interface() const = 0;

  // create a new key based on a password
  // if iterationCount == 0, then iteration count will be determined
  // by newKey functon and filled in.
  // If iterationCount == 0, then descriedFunctionDuration is how many
  // milliseconds the password derivation function should take to run.
  virtual CipherKey newKey(const char *password, int passwdLength,
                           int &iterationCount, long desiredFunctionDuration,
                           const unsigned char *salt, int saltLen) = 0;

  // deprecated - for backward compatibility
  virtual CipherKey newKey(const char *password, int passwdLength) = 0;
  // create a new random key
  virtual CipherKey newRandomKey() = 0;

  // data must be len encodedKeySize()
  virtual CipherKey readKey(const unsigned char *data,
                            const CipherKey &encodingKey,
                            bool checkKey = true) = 0;
  virtual void writeKey(const CipherKey &key, unsigned char *data,
                        const CipherKey &encodingKey) = 0;
  virtual std::string encodeAsString(const CipherKey &key,
                                     const CipherKey &encodingKey);

  // for testing purposes
  virtual bool compareKey(const CipherKey &A, const CipherKey &B) const = 0;

  // meta-data about the cypher
  virtual int keySize() const = 0;
  virtual int encodedKeySize() const = 0;  // size
  virtual int cipherBlockSize() const = 0; // size of a cipher
                                           // block
  // fill the supplied buffer with random data
  // The data may be pseudo random and might not be suitable for key
  // generation. For generation keys, uses newRandomkey() instead.
  // Returns true on Success, false on failure.
  virtual bool randomize(unsigned char *buf, int len,
                         bool strongRandom) const = 0;

  // 64 bit MAC of the data with the given key
  virtual uint64_t MAC_64(const unsigned char *src, int len,
                          const CipherKey &key,
                          uint64_t *chainedIV = 0) const = 0;
  // based on reductions of MAC_64
  unsigned int MAC_32(const unsigned char *src, int len, const CipherKey &key,
                      uint64_t *chainedIV = 0) const;
  unsigned int MAC_16(const unsigned char *src, int len, const Cipher)
};
} // namespace encfs

#endif
