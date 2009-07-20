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

  int process    = processFd();
  sandbox_munmap(TLS::getTLSValue<void *>(TLS_MEM), 4096);
  if (write(sys, process, &request, sizeof(request)) != sizeof(request)) {
    die("Failed to forward exit() request [sandbox]");
  }
  for (;;) {
    sys._exit(status);
  }
}

bool Sandbox::process_exit(int sandboxFd, int threadFdPub, int threadFd,
                           SecureMem::Args* mem) {
  int data = __NR_exit;
  SysCalls sys;
  write(sys, threadFdPub, &data, sizeof(data));
  return true;
}

} // namespace
