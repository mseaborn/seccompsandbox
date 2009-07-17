#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_exit(int status) {
  SysCalls sys;
  write(sys, 2, "exit()\n", 7);
  struct {
    int   sysnum;
    pid_t tid;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_exit;
  request.tid             = tid();

  int process             = processFd();
  sandbox_munmap(TLS::getTLSValue<void *>(TLS_MEM), 4096);
  if (write(sys, process, &request, sizeof(request)) != sizeof(request)) {
    die("Failed to forward exit() request [sandbox]");
  }
  for (;;) {
    sys._exit(status);
  }
}

void Sandbox::process_exit(int sandboxFd, int threadFdPub, int threadFd,
                           SecureMem::Args* mem) {
  int data[] = { __NR_exit, 0 };
  SysCalls sys;
  write(sys, threadFdPub, data, sizeof(data));
}

} // namespace
