#ifndef _READPASSPHRASE_H_
#define _READPASSPHRASE_H_

#include <sys/types.h>

#ifndef HAVE_READPASSPHRASE

#define RPP_ECHO_OFF 0x00   /* Trun off echo (default) */
#define RPP_ECHO_ON 0x01    /* Leave echo on */
#define RPP_REQUIRE_TTY 0x02    /* Fail if there is no try */
#define RPP_FORCELOWER 0x04 /* Force input lower case */
#define RPP_FORCEUPPER 0x08 /* Force input upper case. */
#define RPP_SEVENBIT 0x10   /* Strip the high bit from input */

#ifdef __cplusplus
extern "C"
#endif

char* readpassphrase(const char* prompt, char* buf, size_t bufSize, int flags);
#endif

#endif
