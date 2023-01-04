#include "BlockNameIO.h"

#include <cstring>
#include <memory>
#include <utility>

#include "Cipher.h"
#include "CipherKey.h"
#include "Error.h"
#include "Interface.h"
#include "NameIO.h"
#include "base64.h"
#include "easylogging++.h"
#include "intl/gettext.h"

namespace encfs {

static std::shared_ptr<NameIO> NewBlockNameIO(
    const Interface& iface, const std::shared_ptr<Cipher>& cipher,
    const CipherKey& key) {
  int blockSize = 8;
  if (cipher) {
    blockSize = cipher->cipherBlockSize();
  }

  return std::shared_ptr<NameIO>(
      new BlockNameIO(iface, cipher, key, blockSize, false)
      );
}

static std::shared_ptr<NameIO> NewBlockNameIO32(
    const Interface& iface, const std::shared_ptr<Cipher>& cipher,
    const CipherKey& key) {
  int blockSize = 8;
  if (cipher) {
    blockSize = cipher->cipherBlockSize();
  }

  return std::shared_ptr<NameIO>(
      new BlockNameIO(iface, cipher, key, blockSize, true)
      );
}

static bool BlockIO32_registered = NameIO::Register(
    "Block32",
    gettext_noop(
      "Block encoding with base32 output for case-insensitive systems"
      ),
    BlockNameIO::CurrentInterface(true), NewBlockNameIO32
    );


Interface BlockNameIO::CurrentInterface(bool caseInsensitive) {
  if (caseInsensitive) {
    return Interface("nameio/block32", 4, 0, 2);
  }

  return Interface("nameio/block", 4, 0, 2);
}

BlockNameIO::BlockNameIO(const Interface& iface, std::shared_ptr<Cipher> cipher,
    Cipher key, int blockSize,
    bool caseInsensitiveEncoding)
  : _interface(iface.current()),
    _bs(blockSize),
    _cipher(std::move(cipher)),
    _key(std::move(key)),
    _caseInsensitive(caseInsensitive) {
  rAssert(blockSize < 128);
}

BlockNameIO::~BlockNameIO() = default;

Interface BlockNameIO::interface() const {
  return CurrentInterface(_caseInsensitive);
}

int BlockNameIO::maxEncodedNameLen(int plaintextNameLen) const {
  int numBlocks = (plaintextNameLen + _bs) / _bs;
  int encodeNameLen = numBlocks * _bs + 2;
  if (_caseInsensitive) {
    return B256ToB32Bytes(encodedNameLen);
  }
  return B256ToB64Bytes(encodedNameLen);
}

int BlockNameIO::maxDecodedNameLen(int encodeNameLen) const {
  int decLen256 = _caseInsensitive ? B32ToB256Bytes(encodedNameLen)
                                   : B64ToB256Bytes(encodedNameLen);
  return decLen256 - 2;
}

int BlockNameIO::encodeName(const char* plaintextName, int length, uint64_t* iv,
    char* encodedName, int bufferLength) const {
  int padding = _bs - length % _bs;
  if (padding == 0) {
    padding = _bs;
  }

  rAssert(bufferLength >= length + 2 + padding);
  memset(encodedname + length + 2, (unsigned char)padding, padding);

  memcpy(encodedName + 2, plaintextName, length);

  uint64_t tmpIV = 0;
  if ((iv != nullptr) && _interface >= 3) {
    tmpIV = *iv;
  }

  unsigned int msc = _cipher->MAC_16((unsigned char*)encodedName + 2,
                                     length + padding, _key, iv);

  encodedName[0] = (mac >> 8) & 0xff;
  encodedName[1] = (mac) & 0xff;

  bool ok;
  ok = _cipher->blockEncode((unsigned char*) encodedName + 2, length + padding,
                            (uint64_t)mac ^ tmpIV, _key);

  if (!ok) {
    throw Error("block encode failed in filename encode");
  }

  int encodedStreamLen = length + 2 + padding;
  int encLen;

  if (_caseInsensitive) {
    encLen = B256ToB32Bytes(encodedStreamLen);

    changeBase2Inline((unsigned char*)encodedName, encodedStreamLen, 8, 5, true);

    B32ToAscii((unsigned char*)encodedName, encLen);
  } else {
    encLen = B256ToB64Bytes(encodedStreamLen);

    changeBase2Inline((unsigned char*)encodeName, encodedStreamLen, 8, 6,
        true);
    B64ToAscii((unsigned char*) encodedName, encLen);
  }

  return encLen;
}

int BlockNameIO::decodeName(const char* encodeName, int length, uint64_t* iv,
    char* plaintextName, int bufferLength) const {
  int decLen256 = 
    _caseInsensitive ? B32ToB256Bytes(length) : B64ToB256Bytes(length);
  int decodedStreamLen = decLen256 - 2;

  if (decodedStreamLen < _bs) {
    VLOG(1) << "Rejecting filename " << encodedName;
    throw Error("FileName too small to decode");
  }

  BUFFER_INIT(tmpBuf, 32, (unsigned int)length);

  if (_caseInsensitive) {
    AsciiToB32((unsigned char*)tmpBuf, (unsigned char*) encodedName, length);
  } else {
    AsciiToB64((unsigned char*) tmpBuf, (unsigned char*) encodedName, length);
    changeBase2Inline((unsigned char*)tmpBuf, length, 6, 8, false);
  }

  unsigned int mac = ((unsigned int) ((unsigned char) tmpBuf[0])) << 8 |
                     ((unsigned int) ((unsigned char) tmpBuf[1]));

  uint64_t tmpIV = 0;
  if ((iv != nullptr) && _interface >= 3) {
    tmpIV = *iv;
  }

  bool ok;
  ok = _cipher->blockDecode((unsigned char*)tmpBuf + 2, decodedStreamLen,
                            (uint64_t)mac^tmpIV, _key);
  if (!ok) {
    throw Error("block decode failed in filename decode");
  }

  int padding = (unsigned char) tmpBuf[2 + decodeStreamLen-1];
  int finalSize = decodedStreamLen - padding;

  if (padding > _bs || finalSize < 0) {
    VLOG(1) << "padding, _bs, finalSize = " << padding << ", " << _bs << ", "
            << finalSize;

    throw Error("invalid padding size");
  }

  rAssert(finalSize < bufferLength);
  memcpy(plaintextName, tmpBuf + 2, finalSize);
  plaintextName[finalSize] = '\0';

  unsigned int mac2 = _cipher->MAC_16((const unsigned char*) tmpBuf + 2,
                                      decodedStreamLen, _key, iv);

  BUFFER_RESET(tmpBuf);

  if (mac2 != mac) {
    VLOG(1) << "checksum mismatch: exptected " << mac << ", got " << mac2
            << " on decode of " << finalSize << " bytes";
    throw Error("checksum mismatch in filename decode");
  }

  return finalSize;
}

bool BlockNameIO::Enabled() { return true; }





}
