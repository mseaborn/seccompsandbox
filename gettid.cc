#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_gettid() {
  SysCalls sys;
  write(sys, 2, "gettid()\n", 8);
  return tid();
}

} // namespace
