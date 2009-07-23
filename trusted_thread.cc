#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

void Sandbox::createTrustedThread(int processFdPub, int cloneFdPub,
                                  SecureMem::Args* secureMem) {
  SecureMem::Args args                  = { { { { { 0 } } } } };
  args.self                             = &args;
  args.newSecureMem                     = secureMem;
  args.processFdPub                     = processFdPub;
  args.cloneFdPub                       = cloneFdPub;
  asm volatile(
#if defined(__x86_64__)
      "push %%rbx\n"
      "push %%rbp\n"
      "mov  %0, %%rbp\n"          // %rbp = args
      "xor  %%rbx, %%rbx\n"       // initial sequence number
      "lea  999f(%%rip), %%r15\n" // continue in same thread
      "jmp  12f\n"                // create trusted thread

      // TODO(markus): Coalesce the read() operations by reading into a bigger
      // buffer.

      // Parameters:
      //   *%fs: secure memory region
      //         the page following this one contains the scratch space
      //   %r13: thread's side of threadFd
      //   %r15: processFdPub

      // Local variables:
      //   %rbx: sequence number for trusted calls

      // Temporary variables:
      //   %r9: system call number
      //  %rbp: secure memory of previous thread

      // Layout of secure shared memory region (c.f. securemem.h):
      //   0x00: pointer to the secure shared memory region (i.e. self)
      //   0x08: sequence number; must match %rbx
      //   0x10: system call number; passed to syscall in %rax
      //   0x18: first argument; passed to syscall in %rdi
      //   0x20: second argument; passed to syscall in %rsi
      //   0x28: third argument; passed to syscall in %rdx
      //   0x30: fourth argument; passed to syscall in %r10
      //   0x38: fifth argument; passed to syscall in %r8
      //   0x40: sixth argument; passed to syscall in %r9
      //   0x48: stored return address for clone() system call
      //   0x50: stored %rbp value for clone() system call
      //   0x58: stored %rbx value for clone() system call
      //   0x60: stored %rcx value for clone() system call
      //   0x68: stored %rdx value for clone() system call
      //   0x70: stored %rsi value for clone() system call
      //   0x78: stored %rdi value for clone() system call
      //   0x80: stored %r8 value for clone() system call
      //   0x88: stored %r9 value for clone() system call
      //   0x90: stored %r10 value for clone() system call
      //   0x98: stored %r11 value for clone() system call
      //   0xA0: stored %r12 value for clone() system call
      //   0xA8: stored %r13 value for clone() system call
      //   0xB0: stored %r14 value for clone() system call
      //   0xB8: stored %r15 value for clone() system call
      //   0xC0: new shared memory for clone()
      //   0xC8: processFdPub for talking to trusted process
      //   0xCC: cloneFdPub for talking to trusted process
      //   0xD0: cookie assigned to us by the trusted process (TLS_COOKIE)
      //   0xD8: thread id (TLS_TID)
      //   0xE0: threadFdPub (TLS_THREAD_FD)
      //   0x200-0x1000: securely passed verified file name(s)

      // Layout of (untrusted) scratch space:
      //   0x00: syscall number; passed in %rax
      //   0x04: first argument; passed in %rdi
      //   0x0C: second argument; passed in %rsi
      //   0x14: third argument; passed in %rdx
      //   0x1C: fourth argument; passed in %r10
      //   0x24: fifth argument; passed in %r8
      //   0x2C: sixth argument; passed in %r9
      //   0x34: return value

    "0:mov  $2, %%rbx\n"           // %rbx  = initial sequence number

      // Read request from untrusted thread, or from trusted process. In either
      // case, the data that we read has to be considered untrusted.
      // read(threadFd, &scratch, 4)
    "1:xor  %%rax, %%rax\n"        // NR_read
      "mov  %%r13, %%rdi\n"        // fd  = threadFd
      "mov  %%fs:0x0, %%rsi\n"
      "add  $0x1000, %%rsi\n"      // buf = &scratch
      "mov  $4, %%edx\n"           // len = 4
    "2:syscall\n"
      "cmp  $-4, %%rax\n"          // EINTR
      "jz   2b\n"
      "cmp  %%rdx, %%rax\n"
      "jnz  17f\n"                 // exit process

      // Retrieve system call number. It is crucial that we only dereference
      // %fs:0x1000 exactly once. Afterwards, memory becomes untrusted and
      // we must use the value that we have read the first time.
      "mov  %%fs:0x1000, %%eax\n"

      // If syscall number is -1, execute system call from the secure memory
      // area
      "cmp  $-1, %%eax\n"
      "jnz  4f\n"
    "3:cmp  %%rbx, %%fs:0x8\n"
      "jne  17f\n"                 // exit process
      "mov  %%fs:0x10, %%rax\n"
      "mov  %%fs:0x18, %%rdi\n"
      "mov  %%fs:0x20, %%rsi\n"
      "mov  %%fs:0x28, %%rdx\n"
      "mov  %%fs:0x30, %%r10\n"
      "mov  %%fs:0x38, %%r8\n"
      "mov  %%fs:0x40, %%r9\n"
      "cmp %%rbx, %%fs:0x8\n"
      "jne  17f\n"                 // exit process
      "add  $2, %%rbx\n"
      "syscall\n"
      "jmp  8f\n"                  // return result

      // If syscall number is -2, execute locked system call from the
      // secure memory area
    "4:cmp  $-2, %%eax\n"
      "jnz  6f\n"
      "cmp  %%rbx, %%fs:0x8\n"
      "jne  17f\n"                 // exit process
      "mov  %%fs:0x10, %%rax\n"
      "mov  %%fs:0x18, %%rdi\n"
      "mov  %%fs:0x20, %%rsi\n"
      "mov  %%fs:0x28, %%rdx\n"
      "mov  %%fs:0x30, %%r10\n"
      "mov  %%fs:0x38, %%r8\n"
      "mov  %%fs:0x40, %%r9\n"
      "cmp  %%rbx, %%fs:0x8\n"
      "jne  17f\n"                 // exit process

      // clone() has unusual calling conventions and must be handled specially
      "cmp  $56, %%rax\n"          // NR_clone
      "jz   11f\n"

      // exit() terminates trusted thread
      "cmp  $60, %%eax\n"          // NR_exit
      "jz   10f\n"

      // Perform requested system call
      "syscall\n"

      // Unlock mutex
    "5:cmp  %%rbx, %%fs:0x8\n"
      "jne  17f\n"                 // exit process
      "add  $2, %%rbx\n"
      "mov  %%rax, %%r8\n"
      "mov  $56, %%eax\n"          // NR_clone
      "xor  %%rdi, %%rdi\n"        // flags = 0
      "xor  %%rsi, %%rsi\n"        // stack = NULL
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   17f\n"                 // exit process
      "jz   14f\n"                 // unlock and exit
      "mov  %%r8, %%rax\n"
      "jmp  8f\n"                  // return result

      // Check in syscallTable whether this system call is unrestricted
    "6:mov  %%rax, %%r9\n"
      ".globl playground$maxSyscall\n"
      "mov  playground$maxSyscall@GOTPCREL(%%rip), %%r11\n"
      "cmp  0(%%r11), %%eax\n"
      "ja   17f\n"                 // exit process
      "shl  $4, %%rax\n"
      ".globl playground$syscallTable\n"
      "add  playground$syscallTable@GOTPCREL(%%rip), %%rax\n"
      "mov  0(%%rax), %%rax\n"
      "cmp  $1, %%rax\n"
      "jne  17f\n"

      // Default behavior for unrestricted system calls is to just execute
      // them. Read the remaining arguments first.
      "xor  %%rax, %%rax\n"        // NR_read
      "mov  %%r13, %%rdi\n"        // fd  = threadFd
      "add  $4, %%rsi\n"           // buf = &scratch + 4
      "mov  $48, %%edx\n"          // len = 6*sizeof(void *)
    "7:syscall\n"
      "cmp  $-4, %%rax\n"          // EINTR
      "jz   7b\n"
      "cmp  %%rdx, %%rax\n"
      "jnz  17f\n"                 // exit process
      "mov  %%r9, %%rax\n"
      "mov  %%fs:0x1004, %%rdi\n"
      "mov  %%fs:0x100C, %%rsi\n"
      "mov  %%fs:0x1014, %%rdx\n"
      "mov  %%fs:0x101C, %%r10\n"
      "mov  %%fs:0x1024, %%r8\n"
      "mov  %%fs:0x102C, %%r9\n"
      "syscall\n"

      // Return result of system call to sandboxed thread
    "8:mov   %%fs:0x0, %%rsi\n"
      "add   $0x1034, %%rsi\n"     // buf   = &scratch + 52
      "mov   %%rax, (%%rsi)\n"
      "mov   $1, %%eax\n"          // NR_write
      "mov   %%r13, %%rdi\n"       // fd    = threadFd
      "mov   $8, %%edx\n"          // len   = 8
    "9:syscall\n"
      "cmp   %%rdx, %%rax\n"
      "jz    1b\n"
      "cmp   $-4, %%rax\n"         // EINTR
      "jz    9b\n"
      "jmp   17f\n"                // exit process

      // NR_exit:
      // Exit trusted thread after cleaning up resources
   "10:mov   %%fs:0x0, %%rdi\n"    // start  = secure_mem
      "mov   $8192, %%esi\n"       // length = 4096
      "xor   %%rdx, %%rdx\n"       // prot   = PROT_NONE
      "mov   $10, %%eax\n"         // NR_mprotect
      "syscall\n"
      "mov   %%r13, %%rdi\n"       // fd     = threadFd
      "mov   $3, %%eax\n"          // NR_close
      "syscall\n"
      "mov  $56, %%eax\n"          // NR_clone
      "xor  %%rdi, %%rdi\n"        // flags = 0
      "xor  %%rsi, %%rsi\n"        // stack = NULL
      "syscall\n"
      "test %%rax, %%rax\n"
      "jne  15f\n"                 // exit thread
      "jmp  14f\n"                 // unlock mutex

      // NR_clone:
      // Original trusted thread calls clone() to create new nascent
      // thread. This thread is (typically) fully privileged and shares all
      // resources with the caller (i.e. the previous trusted thread),
      // and by extension it shares all resources with the sandbox'd
      // threads.
      // N.B. It is possible to make the thread creation code crash before
      // it releases seccomp privileges. This is generally OK, as it just
      // terminates the program. But if we ever support signal handling,
      // we have to be careful that the user cannot install a SIGSEGV
      // handler that gets executed with elevated privileges.
   "11:mov  %%fs:0x0, %%rbp\n"     // %rbp = old_shared_mem
      "syscall\n"                  // calls NR_clone
      "cmp  $-4095, %%rax\n"
      "jae  5b\n"
      "add  $2, %%rbx\n"
      "test %%rax, %%rax\n"
      "jne  8b\n"                  // return result

      // In nascent thread, now.
      "sub  $2, %%rbx\n"
      "xor  %%r15, %%r15\n"        // Request to return from clone() when done

      // Get thread id of nascent thread
   "12:mov  $186, %%eax\n"         // NR_gettid
      "syscall\n"
      "mov  %%rax, %%r14\n"

      // Nascent thread creates socketpair() for sending requests to
      // trusted thread.
      // We can create the filehandles on the stack. Filehandles are
      // always treated as untrusted.
      // socketpair(AF_UNIX, SOCK_STREAM, 0, fds)
      "push %%r15\n"
      "mov  $53, %%eax\n"          // NR_socketpair
      "mov  $1, %%edi\n"           // domain = AF_UNIX
      "mov  $1, %%esi\n"           // type = SOCK_STREAM
      "xor  %%rdx, %%rdx\n"        // protocol = 0
      "push %%rdx\n"               // used for futex()
      "sub  $8, %%rsp\n"           // sv = %rsp
      "mov  %%rsp, %%r10\n"
      "syscall\n"
      "test %%rax, %%rax\n"
      "jz   19f\n"

      // If things went wrong, we don't have an (easy) way of signaling
      // the parent. For our purposes, it is sufficient to fail with a
      // fatal error.
      "jmp  17f\n"                 // exit process
   "13:mov  $56, %%eax\n"          // NR_clone
      "xor  %%rdi, %%rdi\n"        // flags = 0
      "xor  %%rsi, %%rsi\n"        // stack = NULL
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   17f\n"                 // exit process
      "jne  15f\n"                 // exit thread (no message)
      ".globl playground$syscall_mutex\n"
   "14:mov  playground$syscall_mutex@GOTPCREL(%%rip), %%rdi\n"
      "mov  (%%rdi), %%rdi\n"
      "mov  $4096, %%esi\n"
      "mov  $3, %%edx\n"           // prot = PROT_READ | PROT_WRITE
      "mov  $10, %%eax\n"          // NR_mprotect
      "syscall\n"
      "lock; addl $0x80000000, (%%rdi)\n"
      "jz   15f\n"                 // exit thread
      "mov  $1, %%edx\n"
      "mov  %%rdx, %%rsi\n"        // FUTEX_WAKE
      "mov  $202, %%eax\n"         // NR_futex
      "syscall\n"
   "15:mov  $60, %%eax\n"          // NR_exit
   "16:mov  $1, %%edi\n"           // status = 1
      "syscall\n"
   "17:mov  $1, %%eax\n"           // NR_write
      "mov  $2, %%rdi\n"           // fd = stderr
      "lea  100f(%%rip), %%rsi\n"
      "mov  $101f-100f, %%rdx\n"   // len = strlen(msg)
      "syscall\n"
   "18:mov  $231, %%eax\n"         // NR_exit_group
      "jmp  16b\n"

      // The first page is mapped read-only for use as securely shared memory
   "19:mov  0xC0(%%rbp), %%r12\n"  // %r12 = secure shared memory
      "cmp  %%rbx, 8(%%rbp)\n"
      "jne  17b\n"                 // exit process
      "mov  $10, %%eax\n"          // NR_mprotect
      "mov  %%r12, %%rdi\n"        // addr = secure_mem
      "mov  $4096, %%rsi\n"        // len  = 4096
      "mov  $1, %%rdx\n"           // prot = PROT_READ
      "syscall\n"

      // The second page is used as scratch space by the trusted thread.
      // Make it writable.
      "mov  $10, %%eax\n"          // NR_mprotect
      "lea  4096(%%r12), %%rdi\n"  // addr = secure_mem + 4096
      "mov  $4096, %%rsi\n"        // len  = 4096
      "mov  $3, %%rdx\n"           // prot = PROT_READ | PROT_WRITE
      "syscall\n"

      // Call clone() to create new trusted thread().
      // clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|
      //       CLONE_SYSVSEM|CLONE_UNTRACED|CLONE_SETTLS, stack, NULL, NULL,
      //       tls)
      "mov  4(%%rsp), %%r13d\n"    // %r13  = threadFd
      "mov  $56, %%eax\n"          // NR_clone
      "mov  $0x8D0F00, %%edi\n"    // flags = VM|FS|FILES|SIGH|THR|SYSV|UTR|TLS
      "xor  %%rsi, %%rsi\n"        // stack = NULL
      "xor  %%rdx, %%rdx\n"        // pid   = NULL
      "xor  %%r10, %%r10\n"        // ctid  = NULL
      "mov  %%r12, %%r8\n"         // tls   = new_secure_mem
      "mov  0xC8(%%rbp), %%r15d\n" // %r15  = processFdPub
      "cmp  %%rbx, 8(%%rbp)\n"
      "jne  17b\n"                 // exit process
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   17b\n"                 // exit process
      "jz   0b\n"                  // invoke trustedThreadFnc()

      // Done creating trusted thread. We can now get ready to return to caller
      "mov  0(%%rsp), %%r9d\n"     // %r13 = threadFdPub
      "add  $16, %%rsp\n"

      // Set up thread local storage with information on how to talk to
      // trusted thread and trusted process.
      "lea  0xD0(%%r12), %%rsi\n"  // args   = &secure_mem->cookie;
      "mov  $158, %%eax\n"         // NR_arch_prctl
      "mov  $0x1001, %%edi\n"      // option = ARCH_SET_GS
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  13b\n"                 // exit thread, unlock global mutex

      // Check whether this is the initial thread, or a newly created one
      "pop  %%r15\n"
      "test %%r15, %%r15\n"
      "jne  20f\n"

      // Returning from clone() into the newly created thread is special. We
      // cannot unroll the stack, as we just set up a new stack for this
      // thread. We have to explicitly restore CPU registers to the values
      // that they had when the program originally called clone().
      "sub  $0x80, %%rsp\n"        // redzone compensation
      "mov  0x48(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x50(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x58(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x60(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x68(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x70(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x78(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x80(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x88(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x90(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0x98(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0xA0(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0xA8(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0xB0(%%rbp), %%rax\n"
      "push %%rax\n"
      "mov  0xB8(%%rbp), %%rax\n"
      "push %%rax\n"
      "cmp  %%rbx, 8(%%rbp)\n"
      "jne  17b\n"                 // exit process

      // Nascent thread launches a helper that doesn't share any of our
      // resources, except for pages mapped as MAP_SHARED.
      // clone(0, NULL)
   "20:mov  $56, %%eax\n"          // NR_clone
      "xor  %%rdi, %%rdi\n"        // flags = 0
      "xor  %%rsi, %%rsi\n"        // stack = NULL
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   17b\n"                 // exit process
      "jne  21f\n"

      // Use sendmsg() to send to the trusted process the file handles for
      // communicating with the new trusted thread. We also send the address
      // of the secure memory area and the thread id.
      "mov  0xCC(%%rbp), %%edi\n"  // transport = Sandbox::cloneFdPub()
      "cmp  %%rbx, 8(%%rbp)\n"
      "jne  17b\n"                 // exit process
      "mov  %%r9, %%rsi\n"         // fd0       = threadFdPub
      "mov  %%r13, %%rdx\n"        // fd1       = threadFd
      "push %%r14\n"               // threadId
      "mov  %%esi, 4(%%rsp)\n"     // threadFdPub
      "push %%r12\n"               // secure_mem
      "mov  %%rsp, %%rcx\n"        // buf       = &data
      "mov  $16, %%r8\n"           // len       = sizeof(void*) + 2*sizeof(int)
      ".globl playground$sendFd\n"
      "call playground$sendFd\n"

      // Release syscall_mutex_. This signals the trusted process that
      // it can write into the original thread's secure memory again.
      "mov  $10, %%eax\n"          // NR_mprotect
      "mov  playground$syscall_mutex@GOTPCREL(%%rip), %%rdi\n"
      "mov  (%%rdi), %%rdi\n"
      "mov  $4096, %%esi\n"
      "mov  $3, %%edx\n"           // PROT_READ | PROT_WRITE
      "syscall\n"
      "lock; addl $0x80000000, (%%rdi)\n"
      "jz   18b\n"                 // exit process (no error message)
      "mov  $1, %%edx\n"
      "mov  %%rdx, %%rsi\n"        // FUTEX_WAKE
      "mov  $202, %%eax\n"         // NR_futex
      "syscall\n"
      "jmp  18b\n"                 // exit process (no error message)

      // Wait for trusted process to receive request. It is possible for
      // an attacker to make us continue even before the trusted process is
      // done. This is OK. It'll result in us putting stale values into the
      // new thread's TLS. But that data is considered untrusted anyway.
   "21:push %%rax\n"
      "mov  $1, %%edx\n"           // len       = 1
      "mov  %%rsp, %%rsi\n"        // buf       = %rsp
      "mov  %%r9, %%rdi\n"         // fd        = threadFdPub
   "22:xor  %%rax, %%rax\n"        // NR_read
      "syscall\n"
      "cmp  $-4, %%rax\n"          // EINTR
      "jz   22b\n"
      "cmp  %%rdx, %%rax\n"
      "jne  17b\n"                 // exit process
      "pop  %%rax\n"

      // Release privileges by entering seccomp mode.
      "mov  $157, %%eax\n"         // NR_prctl
      "mov  $22, %%edi\n"          // PR_SET_SECCOMP
      "mov  $1, %%esi\n"
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  17b\n"                 // exit process

      // Return to caller. We are in the new thread, now.
      "xor  %%rax, %%rax\n"
      "test %%r15, %%r15\n"

      // Returning to createTrustedThread()
      "jz   23f\n"
      "jmp  *%%r15\n"

      // Returning to the place where clone() had been called
   "23:pop  %%r15\n"
      "pop  %%r14\n"
      "pop  %%r13\n"
      "pop  %%r12\n"
      "pop  %%r11\n"
      "pop  %%r10\n"
      "pop  %%r9\n"
      "pop  %%r8\n"
      "pop  %%rdi\n"
      "pop  %%rsi\n"
      "pop  %%rdx\n"
      "pop  %%rcx\n"
      "pop  %%rbx\n"
      "pop  %%rbp\n"
      "ret\n"

  "100:.ascii \"Sandbox violation detected, program aborted\\n\"\n"
  "101:\n"

  "999:pop  %%rbp\n"
      "pop  %%rbx\n"
      :
      : "g"(&args)
      : "rax", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15"
#elif defined(__i386__)
// TODO(markus): implement
        "nop"
      :
      : "g"(&args)
#else
#error Unsupported target platform
#endif
);
}

} // namespace
