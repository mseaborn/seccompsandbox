#include "sandbox_impl.h"

namespace playground {

// A gcc code generation bug occasionally prevents us from taking the address
// of the clone_setup_thread() function. So, just make it return its own
// address, instead.
char *clone_setup_thread(void);
__asm__ __volatile__(
    ".pushsection .text, \"ax\", @progbits\n"
  // This function gets called in the child process immediately after a
  // successful call to clone(). It sets up the child's seccomp permissions
  // (or rather the lack thereof) and its local storage.
  // The return address is passed in in %r10/%ebp.
  // As this code runs in the trusted thread, it needs to be careful not to
  // trust any memory contents.
  "_ZN10playground18clone_setup_threadEv:"
  ".type _ZN10playground18clone_setup_threadEv, @function\n"
  #if __WORDSIZE == 64
  // TODO(markus): implement
  // needs to create thread local storage or some other way of keeping track
  // of the threadFd and the secure shared memory region. Needs to launch a
  // new trusted thread
  //
  // Probably need to extend SecureMem to have a thread that shares
  // address space but not file handles. This thread needs to be written
  // in assembly. It can inject a new shared memory segment into
  // the sandbox.
  "call 0f\n"
"0:pop  %rax\n"
  "add  $1f-0b, %rax\n"
  "ret\n"
"1:mov  $1, %esi\n"
  "mov  $22, %edi\n"  // PR_SET_SECCOMP
  "mov  $157, %eax\n" // __NR_prctl
  "syscall\n"
  "jmp  *%r10\n"
  #else
  // TODO(markus): implement
  "call 0f\n"
"0:pop  %eax\n"
  "add  $1f-0b, %eax\n"
  "ret\n"
"1:mov  $1, %ecx\n"
  "mov  $22, %ebx\n"  // PR_SET_SECCOMP
  "mov  $172, %eax\n" // __NR_prctl
  "int  $0x80\n"
  "jmp  *%ebp\n"
  #endif
  ".size _ZN10playground18clone_setup_threadEv, "
      ".-_ZN10playground18clone_setup_threadEv\n"

  // This code relies on the stack layout of the system call wrapper. It
  // passes the stack pointer as an additional argument to sandbox_clone(),
  // so that upon starting the child, register values can be restored and
  // the child can start executing at the correct IP, instead of trying to
  // run in the trusted thread.
  "sandbox_clone:"
  ".globl sandbox_clone\n"
  ".type sandbox_clone, @function\n"
  #if __WORDSIZE == 64
  "lea 8(%rsp), %r9\n"
  "call 1f\n"
"1:addq $_ZN10playground7Sandbox13sandbox_cloneEiPvPiS1_S2_S1_-., 0(%rsp)\n"
  "retq\n"
  #else
  "lea 28(%esp), %eax\n"
  "mov %eax, 24(%esp)\n"
  "jmp _ZN10playground7Sandbox13sandbox_cloneEiPvPiS1_S2_S1_\n"
  #endif
  ".size sandbox_clone, .-sandbox_clone\n"

  ".popsection\n"
);

int Sandbox::sandbox_clone(int flags, void* stack, int* pid, void* tls,
                           int* ctid, void *wrapper_sp) {
  write(2, "clone()\n", 8);
  struct {
    int   sysnum;
    Clone clone_req;
  } __attribute__((packed)) request;
  request.sysnum               = __NR_clone;
  request.clone_req.flags      = flags;
  request.clone_req.stack      = stack;
  request.clone_req.pid        = pid;
  request.clone_req.tls        = tls;
  request.clone_req.ctid       = ctid;
  #if __WORDSIZE == 64
  memcpy(&request.clone_req.regs64, wrapper_sp,
         sizeof(request.clone_req.regs64));
  #else
  memcpy(&request.clone_req.regs32, wrapper_sp,
         sizeof(request.clone_req.regs32));
  #endif

  long rc;
  if (write(processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward clone() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::thread_clone(int fd) {
  die("thread_clone()");
}

void Sandbox::process_clone(int fd) {
  // Read request
  Clone clone_req;
  if (read(fd, &clone_req, sizeof(clone_req)) != sizeof(clone_req)) {
    die("Failed to read parameters for clone() [process]");
  }

  // TODO(markus): add policy restricting parameters for clone
  // TODO(markus): make sandbox multi-threaded
  if ((clone_req.flags & ~CLONE_DETACHED) != (CLONE_VM|CLONE_FS|CLONE_FILES|
      CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|
      CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID)) {
    secureMem().abandonSystemCall(threadFd(), -EPERM);
  } else {
    // clone() has unusual semantics. We don't want to return back into the
    // trusted thread, but instead we need to continue execution at the IP
    // where we got called initially.
    #if __WORDSIZE == 64
    // TODO(markus): For security reasons, we cannot use the stack. Replace the
    // RET instruction with an absolute jump.
    // TODO(markus): Check whether there is a security issue with us not being
    // able to change the shared memory page atomically. In particular, by
    // writing to threadFd(), malicious code could persuade the trusted thread
    // to run the same system call multiple times. Maybe, include a serial
    // number that has to increment sequentially?
    // TODO(markus): This code is currently not thread-safe.
    // B8 38 00 00 00                   MOV  $__NR_clone /* 56 */, %eax
    // 48 BF .. .. .. .. .. .. .. ..    MOV  $..., %rdi
    // 48 BE .. .. .. .. .. .. .. ..    MOV  $..., %rsi
    // 48 BA .. .. .. .. .. .. .. ..    MOV  $..., %rdx
    // 49 BA .. .. .. .. .. .. .. ..    MOV  $..., %r10
    // 49 B8 .. .. .. .. .. .. .. ..    MOV  $..., %r8
    // 0F 05                            SYSCALL
    // 85 C0                            TEST %rax, %rax
    // 75 7B                            JNE  . + 0x7B
    // 4C 8D 15 0C 00 00 00             LEA  0xC(%rip),%r10
    // 48 B8 .. .. .. .. .. .. .. ..    MOV  $..., %rax
    // FF E0                            JMPQ *%rax
    // 48 31 C0                         XOR  %rax, %rax
    // 48 31 ED                         XOR  %rbp, %rbp
    // 48 81 EC 80 00 00 00             SUB  $0x80,%rsp
    // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
    // 51                               PUSH %rcx
    // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
    // 48 BA .. .. .. .. .. .. .. ..    MOV  $0x..., %rdx
    // 48 BE .. .. .. .. .. .. .. ..    MOV  $0x..., %rsi
    // 48 BF .. .. .. .. .. .. .. ..    MOV  $0x..., %rdi
    // 49 B8 .. .. .. .. .. .. .. ..    MOV  $0x..., %r8
    // 49 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %r9
    // 49 BA .. .. .. .. .. .. .. ..    MOV  $0x..., %r10
    // 49 BB .. .. .. .. .. .. .. ..    MOV  $0x..., %r11
    // C3                               RET
    char *mem = reinterpret_cast<char *>(secureMem().mem());
    memcpy(mem,
           "\xB8\x38\x00\x00\x00"
           "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x0F\x05"
           "\x85\xC0"
           "\x75\x7B"
           "\x4C\x8D\x15\x0C\x00\x00\x00"
           "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
           "\xFF\xE0"
           "\x48\x31\xC0"
           "\x48\x31\xED"
           "\x48\x81\xEC\x80\x00\x00\x00"
           "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x51"
           "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
           "\x49\xBB\x00\x00\x00\x00\x00\x00\x00\x00"
           "\xC3", 185);
    *reinterpret_cast<long  *>(mem +   7) = clone_req.flags;
    *reinterpret_cast<void **>(mem +  17) = clone_req.stack;
    *reinterpret_cast<int  **>(mem +  27) = clone_req.pid;
    *reinterpret_cast<void **>(mem +  37) = clone_req.tls;
    *reinterpret_cast<int  **>(mem +  47) = clone_req.ctid;
    *reinterpret_cast<char **>(mem +  70) = clone_setup_thread();
    *reinterpret_cast<void **>(mem +  95) = clone_req.regs64.ret;
    *reinterpret_cast<void **>(mem + 106) = clone_req.regs64.rcx;
    *reinterpret_cast<void **>(mem + 116) = clone_req.regs64.rdx;
    *reinterpret_cast<void **>(mem + 126) = clone_req.regs64.rsi;
    *reinterpret_cast<void **>(mem + 136) = clone_req.regs64.rdi;
    *reinterpret_cast<void **>(mem + 146) = clone_req.regs64.r8;
    *reinterpret_cast<void **>(mem + 156) = clone_req.regs64.r9;
    *reinterpret_cast<void **>(mem + 166) = clone_req.regs64.r10;
    *reinterpret_cast<void **>(mem + 176) = clone_req.regs64.r11;
    #else
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
    // 75 35                            JNE  . + 0x35
    // BD .. .. .. ..                   MOV  $..., %ebp
    // E9 .. .. .. ..                   JMP  ...
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
    char *mem = reinterpret_cast<char *>(secureMem().mem());
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
    *reinterpret_cast<void **>(mem + 23) = clone_req.tls;
    *reinterpret_cast<int  **>(mem + 28) = clone_req.ctid;
    *reinterpret_cast<char **>(mem + 39) = mem + 48;
    *reinterpret_cast<int   *>(mem + 44) = clone_setup_thread() - mem - 48;
    *reinterpret_cast<void **>(mem + 56) = clone_req.regs32.ebx;
    *reinterpret_cast<void **>(mem + 61) = clone_req.regs32.ecx;
    *reinterpret_cast<void **>(mem + 66) = clone_req.regs32.edx;
    *reinterpret_cast<void **>(mem + 71) = clone_req.regs32.esi;
    *reinterpret_cast<void **>(mem + 76) = clone_req.regs32.edi;
    *reinterpret_cast<void **>(mem + 81) = clone_req.regs32.ret2;
    *reinterpret_cast<void **>(mem + 86) = clone_req.regs32.ret1;
    #endif
    secureMem().abandonSystemCall(threadFd(), 0);
  }
}

} // namespace

extern "C" {
void thread_clone(int fd)
  __attribute__((alias("_ZN10playground7Sandbox12thread_cloneEi")));
void process_clone(int fd)
  __attribute__((alias("_ZN10playground7Sandbox13process_cloneEi")));
} // extern "C"
