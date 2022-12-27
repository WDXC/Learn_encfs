#ifndef _ConfigReader_incl_
#define _ConfigReader_incl_

#include <map>
#include <string>

#include "ConfigVar.h"

namespace encfs {
    /*
        Handles Configuration load / store for Encfs filesystems.
        loading existing config file example.

        ConfigReader cfg;
        cfg.load(filesystemConfigFile);

        Interface iface;
        cfg["cipher"] >> iface;

        creating new config example;

        ConfigReader cfg;
        cfg["cipher"] << cipher->interface()
     */

    class ConfigReader {
        public:
            ConfigReader();
            ~ConfigReader();

            bool load(const char* fileName);
            bool save(const char* fileName) const;

            ConfigVar toVar() const;
            bool loadFromVar(ConfigVar& var);

            ConfigVar operator[](const std::string& varName) const;
            ConfigVar& operator[](const std::string& varName);

        private:
            std::map<std::string, ConfigVar> vars;
    };
}

#endif
