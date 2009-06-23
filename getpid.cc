#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_getpid() {
  write(2, "getpid()\n", 8);
  return pid_;
}

void Sandbox::thread_getpid(int fd) {
  die("thread_getpid()");
}

void Sandbox::process_getpid(int fd) {
  die("process_getpid()");
}

} // namespace

extern "C" {
int sandbox_getpid()
   __attribute__((alias("_ZN10playground7Sandbox14sandbox_getpidEv")));
void thread_getpid(int fd)
    __attribute__((alias("_ZN10playground7Sandbox13thread_getpidEi")));
void process_getpid(int fd)
    __attribute__((alias("_ZN10playground7Sandbox14process_getpidEi")));
} // extern "C"
