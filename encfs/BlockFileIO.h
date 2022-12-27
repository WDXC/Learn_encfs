#ifndef _BlockFileIO_incl_
#define _BlockFileIO_incl_

#include <sys/types.h>

#include "FSConfig.h"
#include "FileIO.h"

namespace encfs {
    /*
        Implement block scatter / gather interface. Requires derived classes to 
        implement readOneBlock() / writeOneBlock() at a mininum.

        when a partial block write is requested it will be truned into a read of
        the existing block, merge with the write request, and a write of the full
        block
     */
    class BlockFileIO : public FileIO {
        public:
            BlockFileIO(unsigned int blockSize, const FSConfigPtr& cfg);
            virtual ~BlockFileIO();

            // implement in terms of block.
            virtual ssize_t read(const IORequest& req) const;
            virtual ssize_t write(const IORequest& req);

            virtual unsigned int blockSize() const;

        protected:
            int truncateBase(off_t size, FileIO* base);
            int padFile(off_t oldSize, off_t newSize, bool forceWrite);

            // same as read(), except that the request. offset field is
            // guarenteed to be block aligned, and the request size will not
            // be larger than 1 block
            virtual ssize_t readOneBlock(const IORequest& req) const = 0;
            virtual ssize_t wirteOneBlock(const IORequest& req) = 0;

            ssize_t cacheReadOneBlock(const IORequest& req) const;
            ssize_t cacheWriteOneBlock(const IORequest& req);

            unsigned int _blockSize;
            bool _allowHoles;
            bool _noCache;

            // cache last block for speed...
            mutable IORequest _cache;
    }
}

#endif
