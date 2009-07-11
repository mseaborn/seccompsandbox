#include <map>

#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

// TODO(markus): This should probably be in syscall.c (which might need renaming to syscall.cc)
void* Sandbox::defaultSystemCallHandler(int syscallNum, void* arg0, void* arg1,
                                        void* arg2, void* arg3, void* arg4,
                                        void* arg5) {
  // TODO(markus): The following comment is currently not true, we do intercept these system calls. Try to fix that.

  // We try to avoid intercepting read(), write(), sigreturn(), and exit(), as
  // these system calls are not restricted in Seccomp mode. But depending on
  // the exact instruction sequence in libc, we might not be able to reliably
  // filter out these system calls at the time when we instrument the code.
  SysCalls sys;
  unsigned long rc;
  switch (syscallNum) {
    case __NR_read:
      write(sys, 2, "read()\n", 7);
      rc = sys.read((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_write:
      write(sys, 2, "write()\n", 8);
      rc = sys.write((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_rt_sigreturn:
      write(sys, 2, "rt_sigreturn()\n", 15);
      rc = sys.rt_sigreturn((unsigned long)arg0);
      break;
    case __NR_exit:
      write(sys, 2, "exit()\n", 7);
      rc = sys._exit((long)arg0);
      break;
    default:
      if (syscallNum == __NR_close && arg0 == (void *)2) return 0; // TODO(markus): remove
      if ((unsigned)syscallNum <= maxSyscall &&
          syscallTable[syscallNum].trustedThread == UNRESTRICTED_SYSCALL) {
        { char buf[80]; sprintf(buf, "Unrestricted syscall %d\n", syscallNum); write(sys, 2, buf, strlen(buf)); } // TODO(markus): remove
        struct {
          int          sysnum;
          pid_t        tid;
          void*        unrestricted_req[6];
        } __attribute__((packed)) request = {
          syscallNum, tid(), { arg0, arg1, arg2, arg3, arg4, arg5 } };

        int   thread = TLS::getTLSValue<int>(TLS_THREAD_FD);
        void* rc;
        if (write(sys, thread, &request, sizeof(request)) != sizeof(request) ||
            read(sys, thread, &rc, sizeof(rc)) != sizeof(rc)) {
          die("Failed to forward unrestricted system call");
        }
        return rc;
      } else {
        char buf[80] = { 0 };
        snprintf(buf, sizeof(buf)-1, "Uncaught system call %d\n", syscallNum);
        write(sys, 2, buf, strlen(buf));
        return (void *)-EINVAL;
      }
  }
  if (rc < 0) {
    rc = -sys.my_errno;
  }
  return (void *)rc;
}

void (*Sandbox::getTrustedThreadReturnResult())(void *) {
  void (*fnc)(void *);
  __asm__ __volatile__(
#if __WORDSIZE == 64
      "lea trustedThreadReturnResult(%%rip), %0"
#else
      "nop\n"
// TODO(markus): Enable for 32bit
#endif
      : "=q"(fnc));
  return fnc;
}

void (*Sandbox::getTrustedThreadFnc())() {
  void (*fnc)();
  __asm__ __volatile__(
      "call 999f\n"

#if __WORDSIZE == 64
      // TODO(markus): Coalesce the read() operations by reading into a bigger
      // buffer.
      // TODO(markus): Kill trusted thread, if sandboxed thread dies
      // TODO(markus): Make sure that freeTLS() will be called when thread dies

      // Parameters:
      // %r12: address of secure memory region
      // %r13: thread's side of threadFd
      // %r14: tid of our untrusted thread
      // %r15: public side of processFd

      // Local variables:
      // %rbp: scratch space (untrusted)
      // TODO(markus): %rbx: sequence number for trusted calls

      // Temporary variables (may be destroyed):
      // %r9: system call number


      // Allocate scratch area. This area is untrusted and can be corrupted
      // by other sandboxed threads.
      "mov  $9, %%eax\n"    // NR_mmap
      "xor  %%rdi, %%rdi\n" // start  = NULL
      "mov  $4096, %%esi\n" // length = 4096
      "mov  $3, %%edx\n"    // prot   = PROT_READ | PROT_WRITE
      "mov  $0x22, %%r10\n" // flags  = PRIVATE|ANONYMOUS
      "mov  $-1, %%r8\n"    // fd     = -1
      "xor  %%r9, %%r9\n"   // offset = 0
      "syscall\n"
      "cmp  $-1, %%rax\n"   // MAP_FAILED
      "jnz  3f\n"

    "1:mov  $60, %%eax\n"   // NR_exit
    "2:mov  $1, %%edi\n"    // status = 1
      "syscall\n"
      "jmp  2b\n"

    "3:mov  %%rax, %%rbp\n" // %rbp = mmap(NULL, 4096, READ|WRITE, PRIV|ANON)

      // Read request from untrusted thread
      // read(threadFd, &scratch, 8)
    "4:xor  %%rax, %%rax\n" // NR_read
      "mov  %%r13, %%rdi\n" // fd  = threadFd
      "mov  %%rbp, %%rsi\n" // buf = &scratch
      "mov  $8, %%edx\n"    // len = 8
    "5:syscall\n"
      "cmp  $-4, %%rax\n"   // EINTR
      "jz   5b\n"
      "cmp  %%rdx, %%rax\n"
      "jnz  1b\n"

      // If syscall number is -1, execute code from the secure memory area
      "mov  0(%%rbp), %%eax\n"
      "cmp  $-1, %%eax\n"
      "jnz  6f\n"
      "jmp  *%%r12\n"

      // Look up handler function in syscallTable
    "6:mov  %%rax, %%r9\n"
      "mov  maxSyscall@GOTPCREL(%%rip), %%r11\n"
      "cmp  0(%%r11), %%eax\n"
      "ja   1b\n"
      "shl  $3, %%rax\n"
      "mov  %%rax, %%r11\n"
      "shl  $1, %%rax\n"
      "add  %%r11, %%rax\n"
      "add  syscallTable@GOTPCREL(%%rip), %%rax\n"
      "mov  8(%%rax), %%rax\n"
      "cmp  $-1, %%rax\n"
      "jz   7f\n"

      // TODO(markus): temporarily set up a stack and pass appropriate parameters, so that this can be tested with C code
      "lea  4096(%%rbp), %%rsp\n"        // TODO(markus): remove
      "mov  %%r15, %%rdi\n" // processFd // TODO(markus): remove
      "mov  %%r14, %%rsi\n" // tid       // TODO(markus): remove
      "mov  %%r13, %%rdx\n" // threadFd  // TODO(markus): remove
      "mov  %%r12, %%rcx\n" // mem       // TODO(markus): remove
      "call *%%rax\n"                    // TODO(markus): remove
      "jmp  4b\n"                        // TODO(markus): remove

      // Call handler function for this system call
      // TODO(markus): change thread functions to no longer return the result code themselves. Then have them directly return to trustedThreadReturnResult
      "jmp  *%%rax\n"

      // Default behavior for unrestricted system calls is to just execute
      // them. Read the remaining arguments first.
    "7:xor  %%rax, %%rax\n"    // NR_read
      "mov  %%r13, %%rdi\n"    // fd  = threadFd
      "lea  8(%%rbp), %%rsi\n" // buf = &scratch + 8
      "mov  $48, %%edx\n"      // len = 6*sizeof(void *)
    "8:syscall\n"
      "cmp  $-4, %%rax\n"      // EINTR
      "jz   8b\n"
      "cmp  %%rdx, %%rax\n"
      "jnz  1b\n"
      "mov  %%r9, %%rax\n"
      "mov  0x08(%%rbp), %%rdi\n"
      "mov  0x10(%%rbp), %%rsi\n"
      "mov  0x18(%%rbp), %%rdx\n"
      "mov  0x20(%%rbp), %%r10\n"
      "mov  0x28(%%rbp), %%r8\n"
      "mov  0x30(%%rbp), %%r9\n"
      "syscall\n"

      // Return result of system call to sandboxed thread
    "trustedThreadReturnResult:\n"
    "9:lea   0x38(%%rbp), %%rsi\n" // buf = &scratch + 56
      "mov   %%rax, (%%rsi)\n"
      "mov   $1, %%eax\n"          // NR_write
      "mov   %%r13, %%rdi\n"       // fd = threadFd
      "mov   $8, %%edx\n"          // len = 8
   "10:syscall\n"
      "cmp   %%rdx, %%rax\n"
      "jz    4b\n"
      "cmp   $-4, %%rax\n"         // EINTR
      "jz    10b\n"
      "jmp   1b\n"
#else
// TODO(markus): implement
#endif
  "999:pop  %0\n"
      : "=g"(fnc));
  return fnc;
}

void Sandbox::trustedThread(void *args_) {
#if __WORDSIZE == 64
  ChildArgs *args = reinterpret_cast<ChildArgs *>(args_);
  register void* mem asm("r12") = args->mem;
  register int   fd0 asm("r13") = args->fd0;
  register pid_t tid asm("r14") = args->tid;
  register int   fd1 asm("r15") = args->fd1;
  __asm__ __volatile__(
      "jmp *%0\n"
      :
      : "q"(getTrustedThreadFnc()),
        "q"(mem),
        "q"(fd0),
        "q"(tid),
        "q"(fd1)
      );
#else
      // TODO(markus): implement
#endif
  for (;;);
}

} // namespace
