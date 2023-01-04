#include "MemoryPool.h"

#include <cstring>
#include <openssl/ossl_typ.h>
#include <pthread.h>

#ifdef HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#else
#define VALGRIND_MAKE_MEM_NOACCESS(a, b)
#define VALGRIND_MAKE_MEM_UNDEFINED(a, b)
#endif

#include <openssl/buffer.h>

#define BLOCKDATA(BLOCK) (unsigned char*)(BLOCK)->data->data

namespace encfs {

struct BlockList {
  BlockList* next;
  int size;
  BUF_MEM* data;
};

static BlockList* allocBlock(int size) {
  auto* block = new BlockList;
  block->size = size;
  block->data = BUF_MEM_new();
  VALGRIND_MAKE_MEM_NOACCESS(block->data->data, block->data->max);

  return block;
}

static void freeBlock(BlockList* el) {
  VALGRIND_MAKE_MEM_UNDEFINED(el->data->data, el->data->max);
  BUF_MEM_free(el->data);

  delete el;
}

static pthread_mutex_t gMPoolMutex = PTHREAD_MUTEX_INITIALIZER;

static BlockList* gMemPool = nullptr;

MemBlock MemoryPool::allocate(int size) {
  pthread_mutex_lock(&gMPoolMutex);

  BlockList* parent = nullptr;
  BlockList* block = gMemPool;

  while (block != nullptr && block->size < size) {
    parent = block;
    block = block->next;
  }

  if (block != nullptr) {
    if (parent == nullptr) {
      gMemPool = block->next;
    } else {
      parent->next = block->next;
    }
  }
  pthread_mutex_unlock(&gMPoolMutex);

  if (block == nullptr) {
    block = allocBlock(size);
  }
  block->next = nullptr;

  MemBlock result;
  result.data = BLOCKDATA(block);
  result.internalData = block;

  VALGRIND_MAKE_MEM_UNDEFINED(result.data, size);

  return result;
}

void MemoryPool::release(const MemBlock& mb) {
  pthread_mutex_lock(&gMPoolMutex);
  auto* block = (BlockList*)mb.internalData;

  VALGRIND_MAKE_MEM_UNDEFINED(block->data->data, block->size);
  memset(BLOCKDATA(block), 0, block->size);
  VALGRIND_MAKE_MEM_NOAccess(block->data->data, block->data->max);

  block->next = gMemPool;
  gMemPool = block;

  pthread_mutex_unlock(&gMPoolMutex);
}

void MemoryPool::destroyAll() {
  pthread_mutex_lock(&gMPoolMutex);

  BlockList* block = gMemPool;
  gMemPool = nullptr;

  pthread_mutex_unlock(&gMPoolMutex);

  while (block != nullptr) {
    BlockList* next = block->next;

    freeBlock(block);
    block = next;
  }
}






}
