#ifndef _MemoryPool_incl_
#define _MemoryPool_incl_

namespace encfs {

    struct MemBlock {
        unsigned char* data;
        void* internalData;
        MemBlock();
    };

    inline MemBlock::MemBlock() : data(0), internalData(0) {}

    /*
     * Memory Pool for fixed sized objects.
     *
     * Usage:
     * MemBlock mb = Memory::allocate(size);
     * // do things with storage in mb.data
     * unsigned char *buffer = mb.data;
     * MemoryPool::release(mb);
     */

    namespace MemoryPool {
        MemBlock allocate(int size);
        void release(const MemBlock& el);
        void destroyAll();
    }
}


#endif
