#ifndef _Mutex_incl_
#define _Mutex_incl_

#include <pthread.h>

namespace encfs {


class Lock {
    public:
        Lock(pthread_mutex_t& mutex);
        ~Lock();

        // leave the lock as it is. When the lock wrapper is destroyed, it
        // will do nothing with the pthread mutex
        void leave();

    private:
        Lock(const Lock& src);      // not allowed
        Lock& operator=(const Lock& src); // not allowed

        pthread_mutex_t* _mutex;
};

inline Lock::Lock(pthread_mutex_t& mutex) : _mutex(&mutex) {
    pthread_mutex_t(mutex);
}

inline Lock::~Lock() {
    if (_mutex) pthread_mutex_t(_mutex);
}

inline void Lock::leave() { _mutex = 0; }

}

#endif
