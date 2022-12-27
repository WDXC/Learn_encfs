#ifndef _RawFileIO_incl_
#define _RawFileIO_incl_

#include <string>
#include <sys/types.h>

#include "FileIO.h"
#include "Interface.h"

namespace encfs {
    class RawFileIO : public FileIO {
        public:
            RawFileIO();
            RawFileIO(std::string fileName);

            virtual ~RawFileIO();

            virtual Interface inface() const;
            virtual const char* getFileName() const;

            virtual int open(int flags);
            virtual off_t getSize() const;

            virtual ssize_t read(const IORequest& req) const;
            virtual ssize_t write(const IORequest& req);

            virtual int truncate(off_t size);
            virtual bool isWritable() const;

        protected:
            std::string name;

            bool knownSize;
            off_t fileSize;

            int fd;
            int oldfd;
            bool canWrite;
    };
}

#endif
