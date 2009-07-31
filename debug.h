#ifndef DEBUG_H__
#define DEBUG_H__

#include <map>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>

#include "sandbox_impl.h"

namespace playground {

class Debug {
 public:
  // If debugging is enabled, write a message to stderr.
  static void message(const char* msg);

  // If debugging is enabled, write the name of the syscall and an optional
  // message to stderr.
  static void syscall(int sysnum, const char* msg);

  // Check whether debugging is enabled.
  static bool isEnabled() { return enabled_; }

 private:
  Debug();
  static char* itoa(int n, char *s);

  static Debug debug_;

  static bool  enabled_;
  static int  numSyscallNames_;
  static const char **syscallNames_;
  static std::map<int, std::string> syscallNamesMap_;
};

} // namespace

#endif // DEBUG_H__
