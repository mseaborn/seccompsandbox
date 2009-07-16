#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_getpid() {
  SysCalls sys;
  write(sys, 2, "getpid()\n", 8);
  return pid_;
}

} // namespace
