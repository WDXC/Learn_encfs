#ifndef _NullCipher_incl_
#define _NullCipher_incl_

#include <stdint.h>

#include "Cipher.h"
#include "CipherKey.h"
#include "Interface.h"

namespace encfs {
    /*
        Implements Cipher interface for a pass-through mode. May be useful
        for testing, but that's it
     */
    class NullCipher : public Cipher {
        Interface iface;
        public:
            NullCipher(const Interface& iface);
            virtual ~NullCipher();

            virtual Interface interface() const;

            // create a new key based on a password
            virtual CipherKey newKey(const char* password, int passwdLength,
                                     int& interationCount, long desiredDuration,
                                     const unsigned char* salt, int saltLen);
            virtual CipherKey newKey(const char* password, int passwdlength);
            // create a new random key
            virtual CipherKey newRandomKey();

            // data must be len keySize()
            virtual CipherKey readKey(const unsigned char* data,
                                      const CipherKey& encodingKey, bool checkKey);
            virtual void compareKey(const CipherKey& A, const CipherKey& B) const ;


            // meta-data about the cypher
            virtual int keySize() const;
            virtual int encodeKeySize() const;
            virtual int cipherBlockSize() const;

            virtual bool randomize(unsigned char* buf, int len, bool strongRandom) const;

            virtual uint64_t MAC_64(const unsigned char* data, int len,
                                    const CipherKey& key, uint64_t* chainedIV) const;

            // functional interfaces
            virtual bool streamEncode(unsigned char* in, int len , uint64_t iv64,
                                      const CipherKey& key) const;
            virtual bool streamDecode(unsigned char* in, int len, uint64_t iv64,
                                      const CipherKey& key) const;

            virtual bool blockEncode(unsigned char* buf, int size, uint64_t iv64,
                                     const CipherKey& key) const;
            virtual bool blockDecode(unsigned char* buf, int size, uint64_t iv64,
                                     const CipherKey& key) const;

            // hack to help with static build
            static bool Enable();
    }
}

#endif
