#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_getpid() {
  SysCalls sys;
  write(sys, 2, "getpid()\n", 8);
  return pid_;
}

void Sandbox::thread_getpid(int processFd, pid_t tid, int threadFd, char* mem){
  die("thread_getpid()");
}

void Sandbox::process_getpid(int processFdPub, int sandboxFd, int threadFd,
                             int cloneFdPub, char* mem) {
  die("process_getpid()");
}

} // namespace
