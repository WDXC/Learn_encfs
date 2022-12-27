#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

/* Specification */
#include "autosprintf.h"

#include <cstdarg>  // for va_list
#include <cstdio>   // for NULL, vasprintf
#include <cstdlib>  // for free
#include <cstring>  // for strdup

namespace gnu {
    /* Constructor: takes a format string and the printf arguments*/
    autosprintf::autosprintf(const char* format, ...) {
        va_list args;
        va_start(args, format);
        if (vasprintf(&str, format, args) < 0) {
            str = nullptr;
        }

        va_end(args);
    }

    /* Copy constructor. Necessary because the destructor is nontrivial */
    autosprintf::autosprintf(const autosprintf& src) {
        str = (src.str != nullptr ? strdup(src.str) : nullptr);
    }

    /* Desctructor: frees the temporaily allocated string */
    autosprintf::~autosprintf() {
        free(str);
    }

    /* Conversion to string */
    autosprintf::operator char* () const {
        if (str != nullptr) {
            size_t length = strlen(str) + 1;
            auto* copy = new char[length];
            memcpy(copy, str, length);
            return copy;
        }

        return nullptr;
    }

    autosprintf::operator std::string() const {
        return std::string(str != nullptr ? str : "(error in autosprintf)");
    }
}
