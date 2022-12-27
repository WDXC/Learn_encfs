#ifndef _openssl_incl_
#define _openssl_incl_

namespace encfs {
    void openssl_init(bool isThreaded);
    void openssl_shutdown(bool isThreaded);
}

#endif
