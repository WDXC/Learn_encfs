#include "ConfigReader.h"

#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "ConfigVar.h"
#include "Error.h"

using namespace std;

namespace encfs {

ConfigReader::ConfigReader() = default;

ConfigReader::~ConfigReader() = default;

bool ConfigReader::load(const char* fileName) {
  struct stat stbuf;
  memset(&stbuf, 0, sizeof(struct stat));
  if (lstat(fileName, &stbuf) != 0) {
    return false;
  }

  int size = stbuf.st_size;
  int fd = open(fileName, O_RDONLY);
  if (fd < 0) {
    return false;
  }

  auto* buf = new char[size];

  int res = ::read(fd, buf, size);
  close(fd);

  if (res != size) {
    RLOG(WARNING) << "Partial read of config file, expecting " << size
                  << " bytes, got " << res;
    delete[] buf;
    return false;
  }

  ConfigVar in;
  in.write((unsigned char*) buf, size);
  delete[] buf;

  return loadFromVar(in);
}

bool ConfigReader::loadFromVar(ConfigVar& in) {
  in.resetOffset();

  int numEntries = in.readInt();

  for (int i = 0; i < numEntries; ++i) {
    string key, value;
    in >> key >> value;

    if (key.length() == 0) {
      RLOG(ERROR) << "Invalid key encoding in buffer";
      return false;
    }

    ConfigVar newVar(value);
    vars.insert(make_pair(key, newVar));
  }

  return true;
}

bool ConfigReader::save(const char* fileName) const {
  ConfigVar out = toVar();

  int fd = ::open(fileName, O_RDWR | O_CREAT, 0640);
  if (fd >= 0) {
    int retVal = ::write(fd, out.buffer(), out.size());
    close(fd);
    if (retVal != out.size()) {
      RLOG(ERROR) << "Error writing to config file " << fileName;
      return false;
    }
  } else {
    RLOG(ERROR) << "Unable to open or create file " << fileName;
    return false;
  }

  return true;
}

ConfigVar ConfigReader::toVar() const {
  ConfigVar out;
  out.writeInt(vars.size());
  map<string, ConfigVar>::const_iterator it;

  for (it = vars.begin(); it != vars.end(); ++it) {
    out.writeInt(it->first.size());
    out.write((unsigned char*)it->first.data(), it->first.size());
    out.writeInt(it->second.size());
    out.write((unsigned char*) it->second.buffer(), it->second.size());
  }
  return out;
}

ConfigVar ConfigReader::operator[] (const std::string& varName) const {
  auto it = vars.find(varName);
  if (it == vars.end()) {
    return ConfigVar();
  }

  return it->second;
}

ConfigVar& ConfigReader::operator[](const std::string & varName) {
  return vars[varName];
}




  
}
