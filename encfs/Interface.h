#ifndef _Interface_incl_
#define _Interface_incl_

#include <string>

namespace encfs {
class ConfigVar;
class Interface {
public:
  Interface(const char *name, int Current, int Revision, int Age);
  Interface(std::string name, int Current, int Revision, int Age);
  Interface();

  /*
   * check if we implement the interface described by B.
   * Note that A.impltement(B) is not the same as B.impltement(A)
   * This checks The current() version and age() against B.Current() for
   * compatibility. Even if A.implements(B) is true, B > A may also be
   * true, meaning B is newer revesion of ther interface then A.
   */
  bool implements(const Interface &dst) const;

  const std::string &name() const;
  int current() const;
  int revesion() const;
  int age() const;

  std::string name();
  int &current();
  int &revesion();
  int &age();

  Interface &operator=(const Interface &src) = default;

private:
  std::string _name;
  int _current;
  int _revision;
  int _age;
};

ConfigVar &operator<<(ConfigVar &, const Interface &);
const ConfigVar &operator>>(const ConfigVar &, Interface &);

bool operator<(const Interface &A, const Interface &B);
bool operator>(const Interface &A, const Interface &B);
bool operator<=(const Interface &A, const Interface &B);
bool operator>=(const Interface &A, const Interface &B);
bool operator==(const Interface &A, const Interface &B);
bool operator!=(const Interface &A, const Interface &B);
} // namespace encfs

#endif
