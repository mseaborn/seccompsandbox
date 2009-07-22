#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

// TODO(markus): change this into a function that returns the address of the assembly code. If that isn't possible for sandbox_clone, then move that function into a *.S file
asm(
    ".pushsection .text, \"ax\", @progbits\n"

    // This code relies on the stack layout of the system call wrapper. It
    // passes the stack pointer as an additional argument to sandbox__clone(),
    // so that upon starting the child, register values can be restored and
    // the child can start executing at the correct IP, instead of trying to
    // run in the trusted thread.
    "sandbox_clone:"
    ".globl sandbox_clone\n"
    ".type sandbox_clone, @function\n"
    ".globl sandbox__clone\n"
    #if __WORDSIZE == 64
    "lea 8(%rsp), %r9\n"
    "jmp sandbox__clone@PLT\n"
    #else
    "lea 28(%esp), %eax\n"
    "mov %eax, 24(%esp)\n"
    "jmp sandbox__clone\n"
    #endif
    ".size sandbox_clone, .-sandbox_clone\n"


    "syscallWrapper:"
    ".globl syscallWrapper\n"
    ".type syscallWrapper, @function\n"
    #if __WORDSIZE == 64
    // Save all registers
    "push %rbp\n"
    "mov  %rsp, %rbp\n"
    "push %rbx\n"
    "push %rcx\n"
    "push %rdx\n"
    "push %rsi\n"
    "push %rdi\n"
    "push %r8\n"
    "push %r9\n"
    "push %r10\n"
    "push %r11\n"
    "push %r12\n"
    "push %r13\n"
    "push %r14\n"
    "push %r15\n"

    // Convert from syscall calling conventions to C calling conventions
    "mov %r10, %rcx\n"

    // Check range of system call
    ".globl maxSyscall\n"
    "mov maxSyscall@GOTPCREL(%rip), %r10\n"
    "cmp 0(%r10), %eax\n"
    "ja  1f\n"

    // Retrieve function call from system call table
    "mov %rax, %r10\n"
    "shl $4, %r10\n"
    ".globl syscallTable\n"
    "add syscallTable@GOTPCREL(%rip), %r10\n"
    "mov 0(%r10), %r10\n"

    // Jump to function if non-null, otherwise jump to fallback handler
    "cmp $1, %r10\n"
    "jbe 1f\n"
    "call *%r10\n"
  "0:"

    // Restore CPU registers
    "pop %r15\n"
    "pop %r14\n"
    "pop %r13\n"
    "pop %r12\n"
    "pop %r11\n"
    "pop %r10\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %rdi\n"
    "pop %rsi\n"
    "pop %rdx\n"
    "pop %rcx\n"
    "pop %rbx\n"
    "pop %rbp\n"

    // Remove fake return address
    "add $8, %rsp\n"

    // Return to caller
    "ret\n"

  "1:"
    // Shift registers so that the system call number becomes visible as the
    // first function argument.
    "push %r9\n"
    "mov  %r8, %r9\n"
    "mov  %rcx, %r8\n"
    "mov  %rdx, %rcx\n"
    "mov  %rsi, %rdx\n"
    "mov  %rdi, %rsi\n"
    "mov  %rax, %rdi\n"

    // Call default handler.
    "call defaultSystemCallHandler\n"
    "pop  %r9\n"
    "jmp 0b\n"
    #else
    // Preserve all registers
    "push %ebx\n"
    "push %ecx\n"
    "push %edx\n"
    "push %esi\n"
    "push %edi\n"
    "push %ebp\n"

    // Convert from syscall calling conventions to C calling conventions
    "push %ebp\n"
    "push %edi\n"
    "push %esi\n"
    "push %edx\n"
    "push %ecx\n"
    "push %ebx\n"
    "push %eax\n"

    // Check range of system call
    "cmp syscallTable, %eax\n"
    "ja  1f\n"

    // Retrieve function call from system call table
    "shl  $3, %eax\n"
    "lea  syscallTable, %ebx\n"
    "add  %ebx, %eax\n"
    "mov  0(%eax), %eax\n"

    // Jump to function if non-null, otherwise jump to fallback handler
    "cmp  $1, %eax\n"
    "jbe  1f\n"
    "add  $4, %esp\n"
    "call *%eax\n"
    "add  $24, %esp\n"
  "0:"

    // Restore CPU registers
    "pop  %ebp\n"
    "pop  %edi\n"
    "pop  %esi\n"
    "pop  %edx\n"
    "pop  %ecx\n"
    "pop  %ebx\n"

    // Return to caller
    "ret\n"

  "1:"
    // Call default handler.
    "push $2f\n"
    "push defaultSystemCallHandler\n"
    "ret\n"
  "2:add  $28, %esp\n"
    "jmp 0b\n"

    #endif
    ".size syscallWrapper, .-syscallWrapper\n"
    ".popsection\n"
);


void* Sandbox::defaultSystemCallHandler(int syscallNum, void* arg0, void* arg1,
                                        void* arg2, void* arg3, void* arg4,
                                        void* arg5) {
  // TODO(markus): The following comment is currently not true, we do intercept these system calls. Try to fix that.

  // We try to avoid intercepting read(), write(), and sigreturn(), as
  // these system calls are not restricted in Seccomp mode. But depending on
  // the exact instruction sequence in libc, we might not be able to reliably
  // filter out these system calls at the time when we instrument the code.
  SysCalls sys;
  unsigned long rc;
  switch (syscallNum) {
    case __NR_read:
      rc             = sys.read((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_write:
      rc             = sys.write((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_rt_sigreturn:
      write(sys, 2, "rt_sigreturn()\n", 15);
      rc             = sys.rt_sigreturn((unsigned long)arg0);
      break;
    default:
      if (syscallNum == __NR_close && arg0 == (void *)2) return 0; // TODO(markus): remove
      if ((unsigned)syscallNum <= maxSyscall &&
          syscallTable[syscallNum].handler == UNRESTRICTED_SYSCALL) {
        { char buf[80]; sprintf(buf, "Unrestricted syscall %d\n", syscallNum); write(sys, 2, buf, strlen(buf)); } // TODO(markus): remove
        struct {
          int          sysnum;
          void*        unrestricted_req[6];
        } __attribute__((packed)) request = {
          syscallNum, { arg0, arg1, arg2, arg3, arg4, arg5 } };

        int   thread = threadFdPub();
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
        return (void *)-ENOSYS;
      }
  }
  if (rc < 0) {
    rc               = -sys.my_errno;
  }
  return (void *)rc;
}

} // namespace
