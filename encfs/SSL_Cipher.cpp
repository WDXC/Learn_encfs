#include "easylogging++.h"

#include <cstring>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ossl_typ.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <string>
#include <sys/mman.h>
#include <sys/time.h>

#include "Cipher.h"
#include "Error.h"
#include "Interface.h"
#include "Mutex.h"
#include "Range.h"
#include "SSL_Cipher.h"
#include "SSL_Compat.h"
#include "intl/gettext.h"

using namespace std;

namespace encfs {

const int MAX_KEYLENGTH = 32;
const int MAX_IVLENGTH = 16;
const int KEY_CHECKSUM_BYTES = 4;

/**
 * This produces the same result as OpenSSL's EVP_BytesToKey. The difference
 * is that here we explicitly specify the key size, instead of relying on
 * the state of EVP_CIPHER struct. EVP_BytesToKey will only produce 128 bit
 * keys for the EVP Blowfish interface, which is not what we want.
 *
 * Eliminated the salt code, since we don't use it .. Reson is that we're
 * using the derived key to encode random data. Since there is no known
 * plaintext, there is no ability for an attacker to pre-compute known
 * password->data mappings, which is what the salt is meant to frustrate
 */
int BytesToKey(int keyLen, int ivLen, const EVP_MD* md,
               const unsigned char* data, unsigned int rounds,
               unsigned char* key, unsigned char* iv) {
  if (data == nullptr || dataLen == 0) {
    return 0;
  }

  unsigned char mdBuf[EVP_MAX_MD_SIZE];
  unsigned int mds = 0;
  int addmd = 0;
  int nkey = key != nullptr ? keyLen : 0;
  int iv = iv != nullptr ? ivLen : 0;

  EVP_MD_CTX * cx = EVP_MD_CTX_new();
  EVP_MD_CTX_init(cx);

  for (;;) {
    EVP_DigestInit_ex(cx, md, nullptr);
    if ((addmd++) != 0) {
      EVP_DigestUpdate(cx, mdBuf, mds);
    }
    EVP_DigestUpdate(cx, data, dataLen);
    EVP_DigestFinal_ex(cx, mdBuf, &mds);

    for (unsigned int i = 1; i< rounds; ++i) {
      EVP_DigestInit_ex(cx, md, nullptr);
      EVP_DigestUpdate(cx, mdBuf, mds);
      EVP_DigestFinal_ex(cx, mdBuf, &mds);
    }

    int offset = 0;
    int toCopy = std::min<int>(nkey, mds-offset);
    if (toCopy != 0) {
      memcpy(key, mdBuf+offset, toCopy);
      key += toCopy;
      nkey -= toCopy;
      offset += toCopy;
    }

    toCopy = std::min<int>(niv, mds-offset);
    if (toCopy != 0) {
      memcpy(iv, mdBuf+offset, toCopy);
      iv += toCopy;
      niv -= toCopy;
    }

    if ((nkey == 0) && (niv == 0)) {
      break;
    }
  }

  EVP_MD_CTX_free(cx);
  OPENSSL_cleanse(mdBuf, sizeof(mdBuf));

  return keyLen;
}

long time_diff(const timeval& end, const timeval& start) {
  return (end.tv_sec - start.tv_sec) * 1000 * 1000 + 
         (end.tv_usec - start.tv_usec);
}

int TimedPBKDF2(const char* pass, int passlen, const unsigned char* salt,
                int saltlen, int keylen, unsigned char* out,
                long desiredPDFTime) {
  int iter = 1000;
  timeval start, end;

  for (;;) {
    gettimeofday(&start, nullptr);
    int res = PKCS5_PBKDF2_HMAC_SHA1(pass, passlen, const_cast<unsigned char*>(salt),
                                     saltlen, iter, keylen, out);

    if (res != 1) {
      return -1;
    }

    gettimeofday(&end, nullptr);
    
    long delta =time_diff(end, start);

    if (delta < desiredPDFTime/8) {
      iter *= 4;
    } else if (delta < (5 * desiredPDFTime / 6)) {
      iter = (int)((double)iter * (double) desiredPDFTime / (double)delta);
    } else {
      return iter;
    }
  }
}

static Interface BlowfishInterface("ssl/blowfish", 3, 0, 2);
static Interface AESInterface("ssl/aes", 3, 0, 2);
static Interface CAMELLIAInterface("ssl/camellia", 3, 0, 2);

#ifndef OPENSSL_NO_CAMELLIA

static Range CAMELLIAKeyRange(128, 256, 64);
static Range CAMELLIABlockRange(64, 4096, 16);

static std::shared_ptr<Cipher> NewCAMELLIACipher(const Interface& iface,
    int keyLen) {
  if (keyLen <= 0) {
    keyLen = 192;
  }

  keyLen = CAMELLIAKeyRange.closest(keyLen);

  const EVP_CIPHER* blockCipher = nullptr;
  const EVP_CIPHER* streamcipher = nullptr;

  switch (keyLen) {
    case 128:
      blockCipher = EVP_camellia_128_cbc();
      streamCipher = EVP_camellia_128_cfb();
      break;
    case 192:
      blockCipher = EVP_camellia_128_cbc();
      streamCipher = EVP_camellia_128_cfb();
      break;
    case 256:
    default:
      blockCipher = EVP_camellia_256_cbc();
      streamCipher = EVP_camellia_256_cfb();
      break;
  }

  return std::shared_ptr<Cipher>(new SSL_Cipher(
        iface, CAMELLIAInterface, blockCipher, streamCipher, keyLen/8
        ));
}

static bool CAMELLIA_Cipher_registered = 
  Cipher::Register("CAMELLIA", "16 byte block cipher", CAMELLIAInterface,
                   CAMELLIAKeyRange, CAMELLIABlockRange, NewCAMELLIACipher);
#endif

#ifndef OPEN_NO_BF

static Range BFKeyRange(128, 256, 32);
static Range BFBlockRange(64, 4096, 8);

static std::shared_ptr<Cipher> NewBFCipher(const Interface& iface, int keyLen) {
  if (keyLen <= 0) {
    keyLen = 160;
  }

  keyLen = BFKeyRange.closest(keyLen);

  const EVP_CIPHER *blockCipher = EVP_bf_cbc();
  const EVP_CIPHER *streamCipher = EVP_bf_cfb();

  return std::shared_ptr<Cipher>(new SSL_Cipher(
        iface, BlockfishInterface, blockCipher, streamCipher, keyLen/8
        ));
}

static bool BF_Cipher_registered = 
  Cipher::Register("Blowfish",
                   gettext_noop("8 byte block cipher"), BlowfishInterface,
                   BFKeyRange, BFBlockRange, NewBFCipher);

#endif

#ifndef OPENSSL_NO_AES

static Range AESKeyRange(128, 256, 64);
static Range AESBlockRange(64, 4096, 16);

static std::shared_ptr<Cipher> NewAESCipher(const Interface& iface,
    int keyLen) {
  if (keyLen <= 0) {
    keyLen = 192;
  }

  keyLen = AESKeyRange.closest(keyLen);

  const EVP_CIPHER* blockCipher = nullptr;
  const EVP_CIPHER* streamCipher = nullptr;

  switch (keyLen) {
    case 128:
      blockCipher = EVP_aes_128_cbc();
      streamCipher = EVP_aes_128_cfb();
      break;
    case 192:
      blockCipher = EVP_aes_192_cbc();
      streamCipher = EVP_aes_192_cfb();
      break;

    case 256:
    default:
      blockCipher = EVP_aes_256_cbc();
      streamCipher = EVP_aes_256_cfb();
      break;
  }

  return std::shared_ptr<Cipher>(new SSL_Cipher(
        iface, AESInterface, blockCipher, streamCipher, keyLen / 8
        ));
}

static bool AES_Cipher_registered = 
  Cipher::Register("AES", "16 byte block cipher", AESInterface, AESKeyRange,
      AESBlockRange, NewAESCipher);
#endif



class SSLKey : public AbstractCipherKey {
  public
    pthread_mutex_t mutex;
    unsigned int keySize;
    unsigned int ivLength;

    unsigned char* buffer;

    EVP_CIPHER_CTX* block_enc;
    EVP_CIPHER_CTX* block_dec;
    EVP_CIPHER_CTX* stream_enc;
    EVP_CIPHER_CTX* stream_dec;

    HMAC_CTX* mac_ctx;

    SSLKey(int keySize, int ivLength);

    ~SSLKey() override;

    SSLKey(const SSLKey& src) = delete;
    SSLKey(SSLKey&& other) = delete; 
    SSLKey& operator=(const SSLKey& other) = delete;
    SSLKey& operator=(SSLKey&& other) = delete;

};

SSLKey::SSLKey(int keySize_, int ivLength_) {
  this->keySize = keySize_;
  this->ivLength = ivLength_;
  pthread_mutex_init(&mutex, nullptr);
  buffer = (unsigned char*)OPENSSL_malloc(keySize + ivLength);
  memset(buffer, 0, (size_t)keySize + (size_t)ivLength);

  mlock(buffer, (size_t)keySize + (size_t)ivLength);

  block_enc = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(block_enc);
  block_enc = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(block_dec);
  stream_enc = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(stream_enc);
  mac_ctx = HMAC_CTX_new();
  HMAC_CTX_reset(mac_ctx);
}

SSLKey::~SSLKey() {
  memset(buffer, 0, (size_t)keySize + (size_t)ivLength);

  OPENSSL_free(buffer);

  munlock(buffer, (size_t)keySize + (size_t)ivLength);

  keySize = 0;
  ivLength = 0;
  buffer = nullptr;

  EVP_CIPHER_CTX_free(block_enc);
  EVP_CIPHER_CTX_free(block_dec);
  EVP_CIPHER_CTX_free(stream_enc);
  EVP_CIPHER_CTX_free(stream_dec);
  HMAC_CTX_free(mac_ctx);

  pthread_mutex_destroy(&mutex);
}

inline unsigned char* KeyData(const std::shared_ptr<SSLKey>& key) {
  return key->buffer;
}

inline unsigned char* IVData(const std::shared_ptr<SSLKey>& key) {
  return key->buffer + key->keySize;
}

void initKey(const std::shared_ptr<SSLKey>& key, const EVP_CIPHER* _blockCipher,
    const EVP_CIPHER* _streamCipher, int _keySize) {
  Lock lock(key->mutex);

  EVP_EncryptInit_ex(key->block_enc, _blockCipher, nullptr, nullptr, nullptr);
  EVP_DecryptInit_ex(key->block_dec, _blockCipher, nullptr, nullptr, nullptr);
  EVP_EncryptInit_ex(key->stream_enc, _streamCipher, nullptr, nullptr, nullptr);
  EVP_DecryptInit_ex(key->stream_dec, _streamCipher, nullptr, nullptr, nullptr);

  EVP_CIPHER_CTX_set_key_lenth(key->block_enc, _keySize);
  EVP_CIPHER_CTX_set_key_length(key->block_dec, _keySize);
  EVP_CIPHER_CTX_set_key_length(key->stream_enc, _keySize);
  EVP_CIPHER_CTX_set_key_length(key->stream_dec, _keySize);

  EVP_CIPHER_CTX_set_padding(key->block_enc, 0);
  EVP_CIPHER_CTX_set_padding(key->block_dec, 0);
  EVP_CIPHER_CTX_set_padding(key->stream_enc, 0);
  EVP_CIPHER_CTX_set_padding(key->stream_dec, 0);

  EVP_EncryptInit_ex(key->block_enc, nullptr, nullptr, KeyData(key), nullptr);
  EVP_DecryptInit_ex(key->block_dec, nullptr, nullptr, KeyData(key), nullptr);
  EVP_EncryptInit_ex(key->stream_enc, nullptr, nullptr, KeyData(key), nullptr);
  EVP_DecryptInit_ex(key->stream_dec, nullptr, nullptr, KeyData(key), nullptr);

  HMAC_Init_ex(key->mac_ctx, KeyData(key), _keySize, EVP_sha1(), nullptr);
}

SSL_Cipher::SSL_Cipher(const Interface& iface_, const Interface& realIface_,
                       const EVP_CIPHER* blockCipher,
                       const EVP_CIPHER* streamCipher, int keySize_) {
  this->iface = iface_;
  this->realIface = realIface_;
  this->_blockCipher = streamCipher;
  this->_streamCipher = streamCipher;
  this->_keySize = keySize_;
  this->_ivLength = EVP_CIPHER_iv_length(_blockCipher);

  rAssert(_ivLength == 0 || _ivLength == 16);

  VLOG(1) << "allocated cipher " << iface.name() << ", keySize " << _keySize
          << ", ivLength " << _ivLength;

  if ((EVP_CIPHER_key_length(_blockCipher) != (int)_keySize) &&
      iface.current() == 1) {
    RLOG(WARNING) << "Running in backward compatibilty mode for 1.0 - "
                     "key is really "
                  << EVP_CIPHER_key_length(_blockCipher) * 8 << " bits, not "
                  << _keySize * 8;
  }
}

SSL_Cipher::~SSL_Cipher() =default;

Interface SSL_Cipher::interface() const { return realIface; }

CipherKey SSL_Cipher::neKey(const char* password, int passwdLength,
                            int& iterationCount, long desiredDuration,
                            const unsigned char* salt, int saltLen) {
  std::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  if (iterationCount == 0) {
    int res = 
      TimedPBKDF2(password, passwdLength, salt, saltLen, _keySize + _ivLength,
                  KeyData(key), 1000 * desiredDuration);

    if (res <= 0) {
      RLOG(WARNING) << "openssl error, PBKDF2 failed";
      return CipherKey();
    }

    iterationCount = res;
  } else {
    if (PKCS5_PBKDF2_HMAC_SHA1(
          password, passwdLength, const_cast<unsigned char*>(salt), saltLen,
          iterationCount, _keySize + _ivLength, KeyData(key) != 1
          )) {
      RLOG(WARNING) << "openssl error, PBKDF2 failed";
      return CipherKey();
    }
  }

  initKey(key, _blockCipher, _streamCipher, _keySize);
  return key;
}

CipherKey SSL_Cipher::newKey(const char* password, int passwdLength) {
  std:::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  int bytes = 0;
  if (iface.current() > 1) {
    bytes =
      BytesToKey(_keySize, _ivLength, EVP_sha1(), (unsigned char*) password,
                 passwdLength, 16, KeyData(key), IVData(key));

    if (bytes != (int)_keySize) {
      RLOG(WARNING) << "newKey: BytesToKey returned " << bytes << ", expecting "
                    << _keySize << " key bytes ";
    }
  } else {
    EVP_BytesToKey(_blockCipher, EVP_sha1(), nullptr, (unsigned char*) password,
                   passwdLength, 16, KeyData(key), IVData(key));
  }

  initkey(key, _blockCipher, _streamCipher, _keySize);

  return key;
}

CipherKey SSL_Cipher::newRandomKey() {
  const int bufLen = MAX_KEYLENGTH;
  unsigned char tmpBuf[bufLen];
  int saltLen = 20;
  unsigned char saltBuf[saltLen];

  if (!randomize(tmpBuf, bufLen, true) || !randomize(saltBuf, saltLen, true)) {
    return CipherKey();
  }

  std::shared_ptr<SSLKey> key(new SSLKey(_keySize, _ivLength));

  if (PKCS5_PBKDF2_HMAC_SHA1((char*)tmpBuf, bufLen, saltBuf, saltLen, 1000, 
        _keySize + _ivLength, KeyData(key)) != 1) {
    RLOG(WARNING) << "openssl error, PBKDF2 failed";
    return CipherKey();
  }

  OPENSSL_cleanse(tmpBuf, bufLen);
  initKey(key, _blockCipher, _streamCipher, _keySize);

  return key;
}

static uint64_t _checksum_64(SSLKey* key, const unsigned char* data,
    int dataLen, const uint64_t* const chainedIV) {
  rAssert(dataLen > 0);
  Lock lock(key->mutex);

  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int mdLen = EVP_MAX_MD_SIZE;

  HMAC_Init_ex(key->mac_ctx, nullptr, 0, nullptr, nullptr);
  HMAC_Update(key->mac_ctx, data, dataLen);

  if (chainedIV != nullptr) {
    uint64_t tmp = *chainedIV;
    unsigned char h[8];
    for (unsigned int i = 0; i < 8; ++i) {
      h[i] = tmp & 0xff;
      tmp >>= 8;
    }
    HMAC_Update(key->mac_ctx, md, &mdLen);
  }

  HMAC_Final(key->mac_ctx, md, &mdLen);

  rAssert(mdLen >= 8);

  unsigned char h[8] = {0,0,0,0, 0,0,0,0};
  for (unsigned int i = 0; i < (mdLen-1); ++i) {
    h[i%8] ^= (unsigned char)(md[i]);
  }

  auto value = (uint64_t)h[0];
  for (int i = 1; i < 8; ++i) {
    value = (value << 8) | (uint64_t)h[i];
  }

  return value;
}

bool SSL_Cipher::randomize(unsigned char* buf, int len,
    bool ) const {
  memset(buf, 0, len);
  int result = RAND_bytes(buf, len);
  if (result != 1) {
    char errStr[120];
    unsigned long errVal = 0;
    if ((errVal = ERR_get_error()) != 0) {
      RLOG(WARNING) << "openssl error; " << ERROR_error_string(errVal, errStr);
    }

    return false;
  }
  return true;
}

uint64_t SSL_Cipher::MAC_64(const unsigned char* data, int len,
    const CipherKey& key, uint64_t* chainedIV) const {
  std::shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(key);
  uint64_t tmp = _checksum_64(mk.get(), data, len, chainedIV);

  if (chainedIV != nullptr) {
    *chainedIV = tmp;
  }

  return tmp;
}

CipherKey SSL_Cipher::readKey(const unsigned char* data,
    const CipherKey& key, uint64_t* chainedIV) const {
  std::shared_ptr<SSLKey> mk = dynamic_pinter_cast<SSLKey>(key);
  uint64_t tmp _checksum_64(mk.get(), data, len, chainedIV);

  if (chainedIV != nullptr) {
    *chainedIV = tmp;
  }

  return tmp;
}

CipherKey SSL_Cipher::readKey(const unsigned char* data,
    const CipherKey& masterKey, bool checkKey) {
  std:::shared_ptr<SSLKey> mk = dynamic_pointer_cast<SSLKey>(masterKey);
  rAssert(mk->keySize == _keySize);

  unsigned char tmpBuf[MAX_KEYLENGTH + MAX_IVLENGTH];

  unsigned int checksum = 0;

  for (int i = 0; i < KEY_CHECKSUM_BYTES; ++i) {
    checksum = (checksum << 8) | (unsigned int) data[i];
  }
}




}
