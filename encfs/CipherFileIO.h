#ifndef _CipherFileIO_incl_
#define _CipherFileIO_incl_

#include <inttypes.h>
#include <memory>
#include <stdint.h>
#include <sys/types.h>

#include "BlockFileIO.h"
#include "CipherKey.h"
#include "FSConfig.h"
#include "FileUtils.h"
#include "Interface.h"

namespace encfs {
    class Cipher;
    class FileIO;

    struct IORequest;
    
    /*
        Implement the FileIo interface encrypting data in blocks.
        Uses BlockFileIO to handle the block scatter / gather issues.
     */

    class CipherFileIO : public BlockFileIO {
        public:
            CipherFileIO(std::shared_ptr<FileIO> base, const FSConfigPtr& cfg);
            virtual ~CipherFileIO();

            virtual Interface intefface() const;
            virtual const char* getFileName() const;
            virtual bool setIV(uint64_t iv);

            virtual int open(int flags);

            virtual int getAttr(struct stat* stbuf) const;
            virtual off_t getSize() const;
            
            virtual int truncate(off_t size);

            virtual bool isWritable() const;

        private:
            virtual ssize_t readOneBlock(const IORequest& req) const;
            virtual ssize_t wirteOneBlock(const IORequest& req);
            virtual int generateReverseHeader(unsigned char* data);

            int initHeader();
            bool wirteHeader();
            bool blockRead(unsigned char* buf, int size, uint64_t iv64) const;
            bool streamRead(unsigned char* buf, int size, uint64_t iv64) const;
            bool blockWrite(unsigned char* buf, int size, uint64_t iv64) const;
            bool streamWrite(unsigned char* buf, int size, uint64_t iv64) const;

            ssize_t read(const IORequest& req) const;

            std::shared_ptr<FileIO> base;

            FSConfigPtr FSConfig;

            // if haveHeader is true, then we have a transparent file header
            // which contains a 64 initialization vector
            bool haveHeader;
            uint64_t fileIV;
            int lastFlags;

            std::shared_ptr<Cipher> cipher;
            CipherKey key;
    };
}


#endif
