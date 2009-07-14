#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_exit(int status) {
  SysCalls sys;
  write(sys, 2, "exit()\n", 8);
  struct {
    int   sysnum;
    pid_t tid;
    Exit exit_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_exit;
  request.tid             = tid();
  request.exit_req.status = status;

  int process             = processFd();
  sandbox_munmap(TLS::getTLSValue<void *>(TLS_MEM), 4096);
  if (write(sys, process, &request, sizeof(request)) != sizeof(request)) {
    die("Failed to forward exit() request [sandbox]");
  }
  for (;;) {
    sys._exit(status);
  }
}

void Sandbox::thread_exit(int processFd, pid_t tid, int threadFd, char* mem) {
  die("thread_exit()");
}

void Sandbox::process_exit(int processFdPub, int sandboxFd, int threadFd,
                           int cloneFd, char* mem) {
  // Read request
  Exit exit_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &exit_req, sizeof(exit_req)) != sizeof(exit_req)) {
    die("Failed to read parameters for exit() [process]");
  }

  #if __WORDSIZE == 64
  // 49 BE .. .. .. .. .. .. .. ..   MOV    $0x..., %r14
  // 49 BF .. .. .. .. .. .. .. ..   MOV    $0x..., %r15
  // 41 FF E7                        JMPQ   *%r15
  memcpy(mem,
         "\x49\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x41\xFF\xE7",
         23);
  *reinterpret_cast<long long *>(mem +  2) = exit_req.status;
  *reinterpret_cast<void (**)()>(mem + 12) = getTrustedThreadExitFnc();
  #else
  // TODO(markus): Add code for x86-32
  #endif
  SecureMem::abandonSystemCall(threadFd, 0);
}

} // namespace
