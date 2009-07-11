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

void Sandbox::thread_clone(int processFd, pid_t tid, int threadFd, char* mem) {
  die("thread_clone()");
}

void Sandbox::process_clone(int sandboxFd, int processFd, int threadFd,
                            int cloneFd, char* mem) {
  // Read request
  Clone clone_req;
  SysCalls sys;
  if (read(sys, processFd, &clone_req, sizeof(clone_req)) !=sizeof(clone_req)){
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
    #if __WORDSIZE == 64
    char *next = SecureMem::generateSecureMemSnippet(
        mem, 4096, cloneFd, clone_req.flags, clone_req.stack, clone_req.pid,
        clone_req.ctid, clone_req.tls, &trustedThread);
    if (next + 180 > mem + 4096) {
      die("Insufficient shared memory");
    }
    // TODO(markus): For security reasons, we cannot use the stack. Replace the
    // RET instruction with an absolute jump.
    // TODO(markus): Check whether there is a security issue with us not being
    // able to change the shared memory page atomically. In particular, by
    // writing to threadFd(), malicious code could persuade the trusted thread
    // to run the same system call multiple times. Maybe, include a serial
    // number that has to increment sequentially?
    // TODO(markus): This code is currently not thread-safe.
    // 48 85 C0                         TEST %rax, %rax
    // 0F 85 9E 00 00 00                JNE  . + 0x9F  // Return to trusted thr
    // 48 81 EC 80 00 00 00             SUB  $0x80, %rsp  // Red zone comp.
    // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
    // 51                               PUSH %rcx
    // 48 BB .. .. .. .. .. .. .. ..    MOV  $0x..., %rbx
    // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
    // 48 BA .. .. .. .. .. .. .. ..    MOV  $0x..., %rdx
    // 48 BE .. .. .. .. .. .. .. ..    MOV  $0x..., %rsi
    // 48 BF .. .. .. .. .. .. .. ..    MOV  $0x..., %rdi
    // 48 BD .. .. .. .. .. .. .. ..    MOV  $0x..., %rbp
    // 49 B8 .. .. .. .. .. .. .. ..    MOV  $0x..., %r8
    // 49 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %r9
    // 49 BA .. .. .. .. .. .. .. ..    MOV  $0x..., %r10
    // 49 BB .. .. .. .. .. .. .. ..    MOV  $0x..., %r11
    // 49 BC .. .. .. .. .. .. .. ..    MOV  $0x..., %r12
    // 49 BD .. .. .. .. .. .. .. ..    MOV  $0x..., %r13
    // 49 BE .. .. .. .. .. .. .. ..    MOV  $0x..., %r14
    // 49 BF .. .. .. .. .. .. .. ..    MOV  $0x..., %r15
    // C3                               RET
    // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
    // FF E1                            JMP  *%rcx
    memcpy(next,
           "\x48\x85\xC0"
           "\x0F\x85\x9F\x00\x00\x00"
           "\x48\x81\xEC\x80\x00\x00\x00"
           "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x51"
           "\x48\xBB\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBD\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBB\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBC\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBD\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
           "\xC3"
           "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\xFF\xE1", 180);
    *reinterpret_cast<void **>(next +  18) = clone_req.regs64.ret;
    *reinterpret_cast<void **>(next +  29) = clone_req.regs64.rbx;
    *reinterpret_cast<void **>(next +  39) = clone_req.regs64.rcx;
    *reinterpret_cast<void **>(next +  49) = clone_req.regs64.rdx;
    *reinterpret_cast<void **>(next +  59) = clone_req.regs64.rsi;
    *reinterpret_cast<void **>(next +  69) = clone_req.regs64.rdi;
    *reinterpret_cast<void **>(next +  79) = clone_req.regs64.rbp;
    *reinterpret_cast<void **>(next +  89) = clone_req.regs64.r8;
    *reinterpret_cast<void **>(next +  99) = clone_req.regs64.r9;
    *reinterpret_cast<void **>(next + 109) = clone_req.regs64.r10;
    *reinterpret_cast<void **>(next + 119) = clone_req.regs64.r11;
    *reinterpret_cast<void **>(next + 129) = clone_req.regs64.r12;
    *reinterpret_cast<void **>(next + 139) = clone_req.regs64.r13;
    *reinterpret_cast<void **>(next + 149) = clone_req.regs64.r14;
    *reinterpret_cast<void **>(next + 159) = clone_req.regs64.r15;
    *reinterpret_cast<void **>(next + 170) =
                            (void*)getTrustedThreadReturnResult();
    #else
    // TODO(markus): it is not safe to store ebp and ebx on the stack
    // 55                               PUSH %ebp
    // 53                               PUSH %ebx
    // B8 78 00 00 00                   MOV  $__NR_clone /* 120 */, %eax
    // BB .. .. .. ..                   MOV  $..., %ebx
    // B9 .. .. .. ..                   MOV  $..., %ecx
    // BA .. .. .. ..                   MOV  $..., %edx
    // BE .. .. .. ..                   MOV  $..., %esi
    // BF .. .. .. ..                   MOV  $..., %edi
    // CD 80                            INT  $0x80
    // 85 C0                            TEST %eax, %eax
    // 75 35                            JNE  . + 0x35   // RET
    // BD .. .. .. ..                   MOV  $..., %ebp
    // E9 .. .. .. ..                   JMP  ...        // clone_setup_thread
    // 31 C0                            XOR  %eax, %eax
    // BD 00 00 00 00                   MOV  $0, %ebp
    // BB .. .. .. ..                   MOV  $..., %ebx
    // B9 .. .. .. ..                   MOV  $..., %ecx
    // BA .. .. .. ..                   MOV  $..., %edx
    // BE .. .. .. ..                   MOV  $..., %esi
    // BF .. .. .. ..                   MOV  $..., %edi
    // 68 .. .. .. ..                   PUSH $...
    // 68 .. .. .. ..                   PUSH $...
    // C3                               RET
    // 5B                               POP  %ebx
    // 5D                               POP  %ebp
    // C3                               RET
    memcpy(mem,
           "\x55"
           "\x53"
           "\xB8\x78\x00\x00\x00"
           "\xBB\x00\x00\x00\x00"
           "\xB9\x00\x00\x00\x00"
           "\xBA\x00\x00\x00\x00"
           "\xBE\x00\x00\x00\x00"
           "\xBF\x00\x00\x00\x00"
           "\xCD\x80"
           "\x85\xC0"
           "\x75\x35"
           "\xBD\x00\x00\x00\x00"
           "\xE9\x00\x00\x00\x00"
           "\x31\xC0"
           "\xBD\x00\x00\x00\x00"
           "\xBB\x00\x00\x00\x00"
           "\xB9\x00\x00\x00\x00"
           "\xBA\x00\x00\x00\x00"
           "\xBE\x00\x00\x00\x00"
           "\xBF\x00\x00\x00\x00"
           "\x68\x00\x00\x00\x00"
           "\x68\x00\x00\x00\x00"
           "\xC3"
           "\x5B"
           "\x5D"
           "\xC3", 94);
    *reinterpret_cast<int   *>(mem +  8) = clone_req.flags;
    *reinterpret_cast<void **>(mem + 13) = clone_req.stack;
    *reinterpret_cast<int  **>(mem + 18) = clone_req.pid;
    *reinterpret_cast<int  **>(mem + 23) = clone_req.ctid;
    *reinterpret_cast<void **>(mem + 28) = clone_req.tls;
    *reinterpret_cast<char **>(mem + 39) = mem + 48;
    *reinterpret_cast<int   *>(mem + 44) = 0; // TODO(markus): broken on 32bit
    *reinterpret_cast<void **>(mem + 56) = clone_req.regs32.ebx;
    *reinterpret_cast<void **>(mem + 61) = clone_req.regs32.ecx;
    *reinterpret_cast<void **>(mem + 66) = clone_req.regs32.edx;
    *reinterpret_cast<void **>(mem + 71) = clone_req.regs32.esi;
    *reinterpret_cast<void **>(mem + 76) = clone_req.regs32.edi;
    *reinterpret_cast<void **>(mem + 81) = clone_req.regs32.ret2;
    *reinterpret_cast<void **>(mem + 86) = clone_req.regs32.ret1;
    #endif
    SecureMem::abandonSystemCall(threadFd, 0);
  }
}

} // namespace
