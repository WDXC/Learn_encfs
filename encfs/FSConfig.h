#ifndef _FSConfig_incl_
#define _FSConfig_incl_

#include <memory>
#include <string>
#include <vector>

#include "CipherKey.h"
#include "Interface.h"
#include "encfs.h"

namespace encfs {
enum ConfigType {
  Config_None = 0,
  Config_Prehistoric,
  Config_V3,
  Config_V4,
  Config_V5,
  Config_v6
};

struct EncFS_Opts;
class Cipher;
class NameIO;

struct EncFSConfig {
  ConfigType cfgType;

  std::string creator;
  int subVersion;

  // Interface of cipher
  Interface cipherIface;
  // interface used for file name coding
  Interface nameIface;

  int keySize;   // reported in bits
  int blockSize; // reported in bytes

  std::vector<unsigned char> keyData;
  std::vector<unsigned char> salt;

  int kdfIterations;
  long desiredKDFDuration;

  bool plainData; // do not encrypt file content

  int blockMACBytes;     // MAC header on blocks..
  int blockMACRandBytes; // number of random bytes in the block header

  bool uniqueIV;           // per-file Initialication Vector
  bool externalIVChaining; // IV seeding by filename IV chaining

  bool chainedNameIV; // filename IV chaining
  bool allowHoles;    // allow holes in files (implicit zero blocks)

  EncFSConfig() : keyData(), salt() {
    cfgType = Config_None;
    subVersion = 0;
    plainData = false;
    blockMACBytes = 0;
    blockMACRandBytes = 0;
    uniqueIV = false;
    externalIVChaining = false;
    chainedNameIV = false;
    allowHoles = false;

    kdfIterations = 0;
    desiredKDFDuration = 500;
  }

  // deprecated
  void assignKeyData(const std::string &in);
  void assignKeyData(unsigned char *data, int length);
  void assignSaltData(unsigned char *data, int length);

  unsigned char *getKeyData() const;
  unsigned char *getSaltData() const;

private:
  Cipher makeKey(const char *password, int passwdLen);
};

std::ostream &operator<<(std::ostream &os, const EncFSConfig &cfg);
std::istream &operator>>(std::istream &os, EncFSConfig &cfg);

struct FSConfig {
  std::shared_ptr<EncFSConfig> config;
  std::shared_ptr<EncFS_Opts> opts;

  std::shared_ptr<Cipher> cipher;
  CipherKey key;

  std::shared_ptr<NameIO> nameCoding;

  bool forceDecode;       // force decode on MAC block failures
  bool reverseEncryption; // reverse encryption operation

  bool idleTracking; // turn on idle monitoring of filesystem

  FSConfig()
      : forceDecode(false), reverseEncryption(false), idleTracking(false) {}
};

using FSConfigPtr = std::shared_ptr<FSConfig>;
} // namespace encfs

#endif
