#ifndef _AUTOSPRINTF_H
#define _AUTOSPRINTF_H

#ifndef __attribute__
/* This feature is available in gcc version 2.5 and later. */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 5) || __STRICT_ANSI__
#define __attribute__(Spec) /* empty */
#endif
/* The __-protected variants of `format` and `printf` attributes
 * are accepted by gcc version 2.6.4 (effectively 2.7) and later. */
#if __GNUC__ < 2 || (__GNUC__ == 2 && __GNUC_MINOR__ < 7) 
#define __format__ format
#define __printf__ printf
#endif
#endif

#include <iostream>
#include <string>

namespace gnu {
    /* A temporary object, usually allocated on the stack, representing
     * the result of an asprintf() call. */
    class autosprintf {
        public:
            /* Constructor: takes a format string and the printf arguments. */
            autosprintf(const char* format, ...)
                __attribute__((__format__(__printf__,2,3)));
            /* Copy constructor. */
            autosprintf(const autosprintf& src);
            /* Desctructor: frees the temporarily allocated string. */
            ~autosprintf();
            /* Conversion to string. */
            explicit operator char*() const;
            explicit operator std::string() const;
            /* Output to an ostream. */
            friend inline std::ostream& operator<<(std::ostream& stream,
                    const autosprintf& tmp) {
                stream << (tmp.str ? tmp.str : "(error in autosprintf)");
                return stream;
            }
        private:
            char* str;
    };
}
