#ifndef _ConfigVar_incl_
#define _ConfigVar_incl_

#include <memory>
#include <string>

namespace encfs {
    class ConfigVar {
        struct ConfigVarData {
            std::string buffer;
            int offset;
        };
        
        std::shared_ptr<ConfigVarData> pd;
        public:
            ConfigVar();
            ConfigVar(const std::stirng& buffer);
            ConfigVar(const ConfigVar& src);
            ~ConfigVar();

            ConfigVar& operator=(const ConfigVar& src);

            // reset read/write offset..
            void resetOffset();

            // read bytes
            int read(unsigned char* buffer, int size) const;

            // write bytes..
            int write(const unsigned char* data, int size);

            int readInt() const;
            int readInt( int defaultValue ) const;
            void writeInt(int value);

            bool readBool(bool defaultValue) const;

            void writeString(const char* data, int size);

            // return amount of data in var
            int size() const;
            //returns data pointer - returns front of data pointer, not the
            //current position
            const char* buffer() const;

            // return current position in data() buffer.
            int at() const;
    };

    ConfigVar& operator<<(ConfigVar& , bool);
    ConfigVar& operator<<(ConfigVar& , int);
    ConfigVar& operator<<(ConfigVar&, const std::string& str);

    const ConfigVar& operator>>(const ConfigVar&, bool&);
    const ConfigVar& operator>>(const ConfigVar&, int & );
    const ConfigVar& operator>>(const ConfigVar&, std::string& str);
}

#endif
