#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_exit(int status) {
  SysCalls sys;
  write(sys, 2, "exit()\n", 7);
  struct {
    int       sysnum;
    long long cookie;
  } __attribute__((packed)) request;
  request.sysnum = __NR_exit;
  request.cookie = cookie();

  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request)) {
    die("Failed to forward exit() request [sandbox]");
  }
  for (;;) {
    sys._exit(status);
  }
}

bool Sandbox::process_exit(int parentProc, int sandboxFd, int threadFdPub,
                           int threadFd, SecureMem::Args* mem) {
  SecureMem::lockSystemCall(parentProc, mem);
  SecureMem::sendSystemCall(threadFdPub, true, parentProc, mem, __NR_exit, 0);
  return true;
}

} // namespace
