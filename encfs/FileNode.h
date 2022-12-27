#ifndef _FileNode_incl_
#define _FileNode_incl_

#include <atomic>
#include <inttypes.h>
#include <memory>
#include <pthread.h>
#include <stdint.h>
#include <stdint.h>
#include <sys/types.h>

#include "CipherKey.h"
#include "FSConfig.h"
#include "FileUtils.h"
#include "encfs.h"

#define CANARY_OK 0x46040975
#define CANARY_RELEASED 0x70c5610d
#define CANARY_DESTROYED 0x52cdad90

namespace encfs {
    class Cipher;
    class DirNode;
    class FileIO;

    class FileNode {
        public:
            FileNode(DirNode* parent, const FSConfigPtr& cfg, const char* plaintextName,
                     const char* cipherName, uint64_t fuseFh);
            ~FileNode();

            // Use an atomic type. The canary is accessed without holding any
            // locks
            std::atomic<std::uint32_t> canary;

            // FUSE file handle that is passed to the kernel
            uint64_t fuseFh;

            const char* plaintextName() const;
            const char* cipherName() const;

            // directory portion of plaintextName
            std::string plaintextParent() const;

            // if setIVFirst is true, then the IV changed before the name is
            // changed (default). The reverse is also supported for special
            // cases..
            bool setName(const char* plaintextName, const char* cipherName, uint64_t iv,
                         bool setIVFirst = true);

            // create node
            // If uid/gid are not 0, then chown is used is used change ownership
            // as specified
            int mknod(mode_t mode, dev_t rdev, uid_t uid=0, gid_t gid = 0);

            // Returns < 0 on error (-errno), file descriptor on success
            int open(int flags) const;

            // getAttr returns 0 on success, -errno on failure
            int getAttr(struct stat* stbuf) const;
            off_t getSize() const;

            ssize_t read(off_t offset, unsigned char* data, size_t size) const;
            ssize_t write(off_t offset, unsigned char* data, size_t size) ;

            // truncate the file to a particular size
            int truncate(off_t size);

            // datasync or full sync
            int sync(bool dataSync);
        private:
            // doing locking at the FileNode level isn't as efficient as at the
            // lowest level of RawFileIO, since that means locks are held longer
            // (held during CPU intensive crypto operations!). However it makes
            // it easier to avoid any race conditions with operations such as
            // truncate() which may result in multiple calls down to the FileIO
            // level.
            mutable pthread_mutex_t mutex;

            FSConfigPtr fsConfig;

            std::shared_ptr<FileIO> io;
            std::string _pname;
            std::string _cname;
            DirNode* parent;

        private:
            FileNode(const FileNode& src);
            FileNode& operator=(const FileNode& src);
    };
}


#endif
