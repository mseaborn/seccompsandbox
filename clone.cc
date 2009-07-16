// TODO(markus): set TLS values

#include "sandbox_impl.h"

namespace playground {

int Sandbox::sandbox_clone(int flags, void* stack, int* pid, int* ctid,
                           void* tls, void *wrapper_sp) {
  SysCalls sys;
  write(sys, 2, "clone()\n", 8);
  struct {
    int   sysnum;
    pid_t tid;
    Clone clone_req;
  } __attribute__((packed)) request;
  request.sysnum               = __NR_clone;
  request.tid                  = tid();
  request.clone_req.flags      = flags;
  request.clone_req.stack      = stack;
  request.clone_req.pid        = pid;
  request.clone_req.ctid       = ctid;
  request.clone_req.tls        = tls;

  // Pass along the address on the stack where syscallWrapper() stored the
  // original CPU registers. These registers will be restored in the newly
  // created thread prior to returning from the wrapped system call.
  #if __WORDSIZE == 64
  memcpy(&request.clone_req.regs64, wrapper_sp,
         sizeof(request.clone_req.regs64));
  #else
  memcpy(&request.clone_req.regs32, wrapper_sp,
         sizeof(request.clone_req.regs32));
  #endif

  long rc;
  if (write(sys, processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(sys, threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward clone() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::process_clone(int sandboxFd, int threadFdPub, int threadFd,
                            char* mem) {
  // Read request
  Clone clone_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &clone_req, sizeof(clone_req)) !=sizeof(clone_req)){
    die("Failed to read parameters for clone() [process]");
  }

  // TODO(markus): add policy restricting parameters for clone
  // TODO(markus): make sandbox multi-threaded
  if ((clone_req.flags & ~CLONE_DETACHED) != (CLONE_VM|CLONE_FS|CLONE_FILES|
      CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|
      CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID)) {
    SecureMem::abandonSystemCall(threadFd, -EPERM);
  } else {
    // clone() has unusual semantics. We don't want to return back into the
    // trusted thread, but instead we need to continue execution at the IP
    // where we got called initially.
    SecureMem::Args* args = reinterpret_cast<SecureMem::Args*>(mem);
    #if defined(__x86_64__)
    args->ret = clone_req.regs64.ret;
    args->rbp = clone_req.regs64.rbp;
    args->rbx = clone_req.regs64.rbx;
    args->rcx = clone_req.regs64.rcx;
    args->rdx = clone_req.regs64.rdx;
    args->rsi = clone_req.regs64.rsi;
    args->rdi = clone_req.regs64.rdi;
    args->r8  = clone_req.regs64.r8;
    args->r9  = clone_req.regs64.r9;
    args->r10 = clone_req.regs64.r10;
    args->r11 = clone_req.regs64.r11;
    args->r12 = clone_req.regs64.r12;
    args->r13 = clone_req.regs64.r13;
    args->r14 = clone_req.regs64.r14;
    args->r15 = clone_req.regs64.r15;
    #elif defined(__i386__)
    // TODO(markus): implement
    #else
    #error Unsupported target platform
    #endif
    args->secureCradle = secureCradle();
    args->processFd    = processFdPub_;
    args->cloneFd      = cloneFdPub_;
    randomizedFilename(args->filename);
    SecureMem::sendSystemCall(threadFdPub, true, mem, __NR_clone,
                              clone_req.flags, clone_req.stack, clone_req.pid,
                              clone_req.ctid, clone_req.tls);
  }
}

} // namespace
