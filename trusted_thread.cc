#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

char* Sandbox::randomizedFilename(char *fn) {
  // If /dev/shm does not exist, fall back on /tmp
  SysCalls::kernel_stat sb;
  SysCalls sys;
  if (sys.stat("/dev/shm/", &sb) || !S_ISDIR(sb.st_mode)) {
    strcpy(fn, "/tmp/.sandboxXXXXXX");
  } else {
    strcpy(fn, "/dev/shm/.sandboxXXXXXX");
  }

  // Replace the last six characters with a randomized string
  fn = strrchr(fn, '\000');
  struct timeval tv;
  sys.gettimeofday(&tv, NULL);
  unsigned long long rnd = ((unsigned long long)tv.tv_usec << 16) & tv.tv_sec;
  unsigned long long r = rnd;
  for (int j = 0; j < 6; j++) {
    *--fn = 'A' + (r % 26);
    r /= 26;
  }

  return fn;
}

void Sandbox::createTrustedThread(int processFd, int cloneFd) {
  SecureMem::Args args = { 0 };
  args.secureCradle    = secureCradle();
  args.processFd       = processFd;
  args.cloneFd         = cloneFd;
  randomizedFilename(args.filename);
  syscall_mutex_       = 0x80000000;
  asm volatile(
#if __WORDSIZE == 64
      "push %%rbx\n"
      "push %%rbp\n"
      "mov  %0, %%r12\n"
      "xor  %%rbx, %%rbx\n"
      "lea  0f(%%rip), %%r15\n"
      "jmp  nascent_thread\n"
    "0:pop  %%rbp\n"
      "pop  %%rbx\n"
      :
      : "g"(&args)
      : "rax", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14", "r15"
#else
// TODO(markus): implement
        "nop"
      :
      : "g"(&args)
#endif
);
}

void (*Sandbox::getTrustedThreadFnc())() {
  void (*fnc)();
  asm volatile(
      "call 999f\n"

#if __WORDSIZE == 64
      // TODO(markus): Coalesce the read() operations by reading into a bigger
      // buffer.

      // Parameters:
      //   %r12: address of secure memory region
      //   %r13: thread's side of threadFd
      //   %r14: tid of our untrusted thread
      //   %r15: public side of processFd

      // Local variables:
      //   %rbp: scratch space (untrusted)
      //   %rbx: sequence number for trusted calls

      // Temporary variables (may be destroyed):
      //   %r9: system call number

      // Layout of secure shared memory region:
      //   0x00: sequence number; must match %rbx
      //   0x08: system call number; passed to syscall in %rax
      //   0x10: first argument; passed to syscall in %rdi
      //   0x18: second argument; passed to syscall in %rsi
      //   0x20: third argument; passed to syscall in %rdx
      //   0x28: fourth argument; passed to syscall in %r10
      //   0x30: fifth argument; passed to syscall in %r8
      //   0x38: sixth argument; passed to syscall in %r9
      //   0x40: stored return address for clone() system call
      //   0x48: stored %rbp value for clone() system call
      //   0x50: stored %rbx value for clone() system call
      //   0x58: stored %rcx value for clone() system call
      //   0x60: stored %rdx value for clone() system call
      //   0x68: stored %rsi value for clone() system call
      //   0x70: stored %rdi value for clone() system call
      //   0x78: stored %r8 value for clone() system call
      //   0x80: stored %r9 value for clone() system call
      //   0x88: stored %r10 value for clone() system call
      //   0x90: stored %r11 value for clone() system call
      //   0x98: stored %r12 value for clone() system call
      //   0xA0: stored %r13 value for clone() system call
      //   0xA8: stored %r14 value for clone() system call
      //   0xB0: stored %r15 value for clone() system call
      //   0xB8: address of cradle for new secure memory
      //   0xC0: processFd for talking to trusted process
      //   0xC8: cloneFd for talking to trusted process
      //   0xD0: secure filename for shared memory segment

      // Layout of scratch area:
      //   0x00: syscall number; passed in %rax
      //   0x08: first argument; passed in %rdi
      //   0x10: second argument; passed in %rsi
      //   0x18: third argument; passed in %rdx
      //   0x20: fourth argument; passed in %r10
      //   0x28: fifth argument; passed in %r8
      //   0x30: sixth argument; passed in %r9
      //   0x38: return value

      // Allocate scratch area. This area is untrusted and can be corrupted
      // by other sandboxed threads.
    "0:mov  $9, %%eax\n"           // NR_mmap
      "xor  %%rdi, %%rdi\n"        // start  = NULL
      "mov  $4096, %%esi\n"        // length = 4096
      "mov  $3, %%edx\n"           // prot   = PROT_READ | PROT_WRITE
      "mov  $0x22, %%r10\n"        // flags  = PRIVATE|ANONYMOUS
      "mov  $-1, %%r8\n"           // fd     = -1
      "xor  %%r9, %%r9\n"          // offset = 0
      "syscall\n"
      "mov  %%rax, %%rbp\n"        // %rbp = mmap(0, 4096, RD|WR, PRIV|ANON)
      "cmp  $-1, %%rax\n"          // MAP_FAILED
      "jnz  3f\n"

    "1:mov  $1, %%edi\n"           // status = 1
    "2:mov  $60, %%eax\n"          // NR_exit
      "syscall\n"
      "jmp  2b\n"

    "3:mov  $2, %%rbx\n"

      // Read request from untrusted thread
      // read(threadFd, &scratch, 8)
    "4:xor  %%rax, %%rax\n"        // NR_read
      "mov  %%r13, %%rdi\n"        // fd  = threadFd
      "mov  %%rbp, %%rsi\n"        // buf = &scratch
      "mov  $8, %%edx\n"           // len = 8
    "5:syscall\n"
      "cmp  $-4, %%rax\n"          // EINTR
      "jz   5b\n"
      "cmp  %%rdx, %%rax\n"
      "jnz  1b\n"

      // Retrieve system call number. It is crucial that we only dereference
      // 0(%%rbp) exactly once. Afterwards, memory becomes untrusted and we
      // must use the value that we have read the first time.
      "mov  0(%%rbp), %%eax\n"

      // If NR_exit, terminate trusted thread
      "cmp  $60, %%eax\n"          // NR_exit
      "jz   16f\n"

      // If syscall number is -1, execute system call from the secure memory
      // area
      "cmp  $-1, %%eax\n"
      "jnz  6f\n"
      "cmp  %%rbx, (%%r12)\n"
      "jne  1b\n"
      "mov  0x08(%%r12), %%rax\n"
      "mov  0x10(%%r12), %%rdi\n"
      "mov  0x18(%%r12), %%rsi\n"
      "mov  0x20(%%r12), %%rdx\n"
      "mov  0x28(%%r12), %%r10\n"
      "mov  0x30(%%r12), %%r8\n"
      "mov  0x38(%%r12), %%r9\n"
      "cmp %%rbx, (%%r12)\n"
      "jne  1b\n"
      "add  $2, %%rbx\n"
      "syscall\n"
      "jmp  14f\n"

      // If syscall number is -2, execute locked system call from the
      // secure memory area
    "6:cmp  $-2, %%eax\n"
      "jnz  11f\n"
      ".globl syscall_mutex\n"
      "mov   syscall_mutex@GOTPCREL(%%rip), %%r9\n"
      "lock; incl (%%r9)\n"
    "7:lock; btsl $31, (%%r9)\n"
      "jae  8f\n"
      "mov  (%%r9), %%edx\n"
      "test %%edx, %%edx\n"
      "jns  7b\n"
      "xor  %%r10, %%r10\n"
      "xor  %%rsi, %%rsi\n"        // FUTEX_WAIT
      "mov  %%r9, %%rdi\n"
      "mov  $202, %%eax\n"         // NR_futex
      "syscall\n"
      "jmp  7b\n"
    "8:lock; decl (%%r9)\n"
      "cmp  %%rbx, (%%r12)\n"
      "jne  1b\n"
      "mov  0x08(%%r12), %%rax\n"
      "mov  0x10(%%r12), %%rdi\n"
      "mov  0x18(%%r12), %%rsi\n"
      "mov  0x20(%%r12), %%rdx\n"
      "mov  0x28(%%r12), %%r10\n"
      "mov  0x30(%%r12), %%r8\n"

      // clone() has unusual calling conventions and must be handled specially
      "cmp  $56, %%rax\n"          // NR_clone
      "jz   18f\n"

      "mov  0x38(%%r12), %%r9\n"
      "cmp  %%rbx, (%%r12)\n"
      "jne  1b\n"
      "add  $2, %%rbx\n"
      "syscall\n"
    "9:mov  %%rax, %%r8\n"
      "mov  syscall_mutex@GOTPCREL(%%rip), %%r9\n"
      "lock; addl $0x80000000, (%%r9)\n"
      "je   10f\n"
      "mov  $1, %%edx\n"
      "mov  %%rdx, %%rsi\n"        // FUTEX_WAKE
      "mov  %%r9, %%rdi\n"
      "mov  $202, %%eax\n"         // NR_futex
      "syscall\n"
   "10:mov  %%r8, %%rax\n"
      "jmp  14f\n"

      // Look up handler function in syscallTable
   "11:mov  %%rax, %%r9\n"
      "mov  maxSyscall@GOTPCREL(%%rip), %%r11\n"
      "cmp  0(%%r11), %%eax\n"
      "ja   1b\n"
      "shl  $3, %%rax\n"
      "mov  %%rax, %%r11\n"
      "shl  $1, %%rax\n"
      "add  %%r11, %%rax\n"
      "add  syscallTable@GOTPCREL(%%rip), %%rax\n"
      "mov  8(%%rax), %%rax\n"
      "cmp  $1, %%rax\n"
      "jz   12f\n"

      // TODO(markus): temporarily set up a stack and pass appropriate parameters, so that this can be tested with C code
      "lea  4096(%%rbp), %%rsp\n"        // TODO(markus): remove
      "mov  %%r15, %%rdi\n" // processFd // TODO(markus): remove
      "mov  %%r14, %%rsi\n" // tid       // TODO(markus): remove
      "mov  %%r13, %%rdx\n" // threadFd  // TODO(markus): remove
      "mov  %%r12, %%rcx\n" // mem       // TODO(markus): remove
      "call *%%rax\n"                    // TODO(markus): remove
      "xor  %%rsp, %%rsp\n"              // TODO(markus): remove
      "jmp  14f\n"                       // TODO(markus): remove

      // Call handler function for this system call
      "jmp  *%%rax\n"

      // Default behavior for unrestricted system calls is to just execute
      // them. Read the remaining arguments first.
   "12:xor  %%rax, %%rax\n"        // NR_read
      "mov  %%r13, %%rdi\n"        // fd  = threadFd
      "lea  8(%%rbp), %%rsi\n"     // buf = &scratch + 8
      "mov  $48, %%edx\n"          // len = 6*sizeof(void *)
   "13:syscall\n"
      "cmp  $-4, %%rax\n"          // EINTR
      "jz   13b\n"
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
   "14:lea   0x38(%%rbp), %%rsi\n" // buf = &scratch + 56
      "mov   %%rax, (%%rsi)\n"
      "mov   $1, %%eax\n"          // NR_write
      "mov   %%r13, %%rdi\n"       // fd = threadFd
      "mov   $8, %%edx\n"          // len = 8
   "15:syscall\n"
      "cmp   %%rdx, %%rax\n"
      "jz    4b\n"
      "cmp   $-4, %%rax\n"         // EINTR
      "jz    15b\n"
      "jmp   1b\n"

      // NR_exit:
      // Exit trusted thread after cleaning up resources
   "16:mov   %%rbp, %%rdi\n"       // start = &scratch
      "mov   $4096, %%esi\n"       // length = 4096
      "mov   $11, %%eax\n"         // NR_unmap
      "syscall\n"
      "mov   %%r12, %%rdi\n"       // start = secure_mem
      "mov   $4096, %%esi\n"       // length = 4096
      "mov   $11, %%eax\n"         // NR_unmap
      "syscall\n"
      "mov   %%r13, %%rdi\n"       // fd = threadFd
      "mov   $3, %%eax\n"          // NR_close
      "syscall\n"
      "xor   %%rdi, %%rdi\n"       // status = 0
   "17:mov   $60, %%eax\n"         // NR_exit
      "syscall\n"
      "jmp   17b\n"

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
   "18:cmp  %%rbx, (%%r12)\n"
      "jne  1b\n"
      "add  $2, %%rbx\n"
      "syscall\n"               // calls NR_clone
      "cmp  $-4095, %%rax\n"
      "jae  9b\n"
      "test %%rax, %%rax\n"
      "je   21f\n"

      // In the original thread, wait for the mutex to be released. This is
      // necessary so that the child can read all of its parameters. The
      // mutex can potentially be attacked and we could be tricked into
      // continuing the original thread early. This is OK. In the worst case,
      // the trusted process would get tricked into clobbering our shared
      // memory region early. But we verify the sequence number after each
      // read from that region, and terminate the program in case of a
      // mismatch.
      "lock; incl (%%r9)\n"
      "mov  %%r9, %%rdi\n"      // uaddr
   "19:mov  (%%r9), %%edx\n"
      "test %%edx, %%edx\n"
      "js   20f\n"
      "lock; decl (%%r9)\n"
      "mov  $1, %%edx\n"
      "mov  %%rdx, %%rsi\n"     // FUTEX_WAKE
      "mov  $202, %%eax\n"      // NR_futex
      "syscall\n"
      "jmp  14b\n"
   "20:xor  %%rsi, %%rsi\n"     // op      = FUTEX_WAIT
      "xor  %%r10, %%r10\n"     // timeout = NULL
      "mov  $202, %%rax\n"      // NR_futex
      "syscall\n"
      "jmp  19b\n"
   "21:sub  $2, %%rbx\n"
      "xor  %%r15, %%r15\n"

      // Nascent thread creates socketpair() for sending requests to
      // trusted thread.
      // We can create the filehandles on the stack. Filehandles are
      // always treated as untrusted.
      // socketpair(AF_UNIX, SOCK_STREAM, 0, fds)
    "nascent_thread:"
      "push %%r15\n"
      "mov  $53, %%eax\n"       // NR_socketpair
      "mov  $1, %%edi\n"        // domain = AF_UNIX
      "mov  $1, %%esi\n"        // type = SOCK_STREAM
      "xor  %%rdx, %%rdx\n"     // protocol = 0
      "push %%rdx\n"            // used for futex()
      "sub  $8, %%rsp\n"        // sv = %rsp
      "mov  %%rsp, %%r10\n"
      "syscall\n"
      "test %%rax, %%rax\n"
      "jz   28f\n"

      // If things went wrong, we don't have an (easy) way of signaling
      // the parent. For our purposes, it is sufficient to fail with a
      // fatal error.
   "22:mov  $231, %%r8d\n"      // NR_exit_group
      "jmp  24f\n"
   "23:mov  $60, %%r8d\n"       // NR_exit
   "24:mov  syscall_mutex@GOTPCREL(%%rip), %%rdi\n"
      "lock; addl $0x80000000, (%%rdi)\n"
      "je   25f\n"
      "mov  $1, %%edx\n"
      "mov  %%rdx, %%rsi\n"     // FUTEX_WAKE
      "mov  $202, %%eax\n"      // NR_futex
      "syscall\n"
   "25:mov  %%r8, %%rax\n"
   "26:mov  $1, %%edi\n"        // status = 1
      "syscall\n"
   "27:mov  $60, %%eax\n"       // NR_exit
      "jmp  26b\n"

      // Get thread id of newly created thread
   "28:mov  $186, %%eax\n"      // NR_gettid
      "syscall\n"
      "mov  %%rax, %%r14\n"

      // Nascent thread creates another temporary thread that shares
      // address space, but does not share filehandles.
      // clone(CLONE_VM|CLONE_UNTRACED|CLONE_PARENT_SETTID|
      //       CLONE_CHILD_CLEARTTID, stack, pid, tls, ctid)
      "mov  $56, %%eax\n"       // NR_clone
      "mov  $0xB00100, %%edi\n" // flags = VM|UNTRACED|PRNT_SETTID|CLD_CLEAR
      "mov  %%rsp, %%rsi\n"     // stack = %rsp
      "lea  8(%%rsp), %%rdx\n"  // pid   = NULL
      "lea  8(%%rsp), %%r10\n"  // ctid  = NULL
      "xor  %%r8, %%r8\n"       // tls   = NULL
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   22b\n"              // exit process
      "jnz  29f\n"

      // Temporary thread tries to exclusively create file for file
      // name that it has received in the write-protected snippet.
      // open("/dev/shm/.sandboxXXXXXX", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600)
      "mov  $2, %%eax\n"        // NR_open
      "lea  0xD0(%%r12), %%rdi\n" // pathname = "/dev/shm/.sandboxXXXXXX"
      "mov  $0x200C2, %%esi\n"  // flags    = O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW
      "mov  $0600, %%rdx\n"     // mode     = 0600
      "syscall\n"
      "cmp  %%rbx, (%%r12)\n"
      "jne  22b\n"              // exit process

      // If open() fails, exit. TODO(markus): add error handling
      "test %%rax, %%rax\n"
      "js   27b\n"              // exit thread
      "mov  %%rax, %%r13\n"     // %r13 = secureMemFd

      // Unlink file.
      // unlink("/dev/shm/.sandboxXXXXXX")
      "mov  $87, %%eax\n"       // NR_unlink
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  27b\n"              // exit thread

      // Ensure that the file is at least one page long. This is necessary
      // in order to call mmap().
      "mov  $77, %%eax\n"       // NR_ftruncate
      "mov  %%r13, %%rdi\n"     // fd
      "mov  $4096, %%esi\n"     // length = 4096
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  27b\n"              // exit thread

      // Call mmap() to create shared memory in a well-known
      // location. This location must have guard pages on both
      // sides. As there is only one such well-known location, the
      // trusted process has to ensure that only one clone() request
      // is pending at any given time.
      // mmap(Sandbox::secure(), PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0)
      "mov  $9, %%eax\n"        // NR_mmap
      "mov  0xB8(%%r12), %%rdi\n"// start  = Sandbox::secureCradle()
      "cmp  %%rbx, (%%r12)\n"
      "jne  22b\n"              // exit process
      "mov  $5, %%edx\n"        // prot   = PROT_READ | PROT_EXEC
      "mov  $17, %%r10\n"       // flags  = MAP_SHARED | MAP_FIXED
      "mov  %%r13, %%r8\n"      // fd
      "xor  %%r9, %%r9\n"       // offset = 0
      "syscall\n"
      "cmp  %%rax, %%rdi\n"
      "jnz  27b\n"              // exit thread

      // Call fork() to unshare the address space then exit the
      // temporary thread.
      "mov  $57, %%eax\n"       // NR_fork
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  27b\n"              // exit thread

      // The fork()'d process uses sendmsg() to send the file handle
      // for the shared memory region to the trusted process. It also
      // sends the file handle for talking to the trusted thread, and
      // the new pid. The new pid is used as cookie by the trusted
      // process to decide where to send responses, too.
      "mov  0xC8(%%r12), %%edi\n" // transport = Sandbox::cloneFd()
      "cmp  %%rbx, (%%r12)\n"
      "jne  22b\n"              // exit process
      "mov  %%r13, %%rsi\n"     // fd0       = fd
      "movl 0(%%rsp), %%edx\n"  // fd1       = %rsp[0]
      "mov  4(%%rsp), %%ecx\n"  // fd2       = %rsp[1]
      "push %%r14\n"
      "mov  %%rsp, %%r8\n"      // buf       = &tid
      "mov  $4, %%r9\n"         // len       = sizeof(int)
      ".globl sendFd\n"
      "call sendFd\n"
      "jmp  22b\n"              // exit process

      // Nascent thread calls futex() to wait for temporary thread.
      // futex(&tid, FUTEX_WAIT, tid, NULL)
   "29:cmpl %%eax, 8(%%rsp)\n"
      "jnz  30f\n"
      "lea  8(%%rsp), %%rdi\n"  // uaddr
      "xor  %%rsi, %%rsi\n"     // op      = FUTEX_WAIT
      "mov  %%rax, %%rdx\n"     // val     = tid
      "xor  %%r10, %%r10\n"     // timeout = NULL
      "mov  $202, %%rax\n"      // NR_futex
      "syscall\n"

      // Trusted thread returns from futex() and tries to mremap()
      // shared memory from its original fixed location. It can do
      // this by temporarily increasing the size of the mapping
   "30:mov  %%r12, %%rbp\n"     // rbp     = old_shared_mem
      "mov  $25, %%eax\n"       // NR_mremap
      "mov  0xB8(%%rbp), %%rdi\n"//old_address = Sandbox::secureCradle()
      "cmp  %%rbx, (%%rbp)\n"
      "jne  22b\n"              // exit process
      "mov  $4096, %%esi\n"     // old_size    = 4096
      "mov  $8192, %%edx\n"     // new_size    = 8192
      "mov  $1, %%r10\n"        // flags       = MREMAP_MAYMOVE
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  22b\n"              // exit process  TODO(markus): better error handling
      "mov  %%rax, %%rdi\n"     // old_address = mremap()
      "mov  $25, %%eax\n"       // NR_mremap
      "mov  $8192, %%esi\n"     // old_size    = 8192
      "mov  $4096, %%edx\n"     // new_size    = 4096
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  22b\n"              // exit process TODO(markus): better error handling
      "mov  %%rax, %%r12\n"     // %r12   = secure_mem
      "mov  $9, %%eax\n"        // NR_mmap
      "movq 0xB8(%%rbp), %%rdi\n"//start = Sandbox::secureCradle()
      "cmp  %%rbx, (%%rbp)\n"
      "jne  22b\n"              // exit process
      "mov  $4096, %%esi\n"     // length = 4096
      "xor  %%rdx, %%rdx\n"     // prot   = PROT_NONE
      "mov  $0x32, %%r10\n"     // flags  = PRIVATE|FIXED|ANONYMOUS
      "mov  $-1, %%r8\n"        // fd     = -1
      "xor  %%r9, %%r9\n"       // offset = NULL
      "syscall\n"
      "cmp  %%rax, %%rdi\n"
      "jne  22b\n"              // exit process

      // Call clone() to create new trusted thread().
      "mov  4(%%rsp), %%r13d\n" // %r13  = threadFd
      "mov  $56, %%eax\n"       // NR_clone
      "mov  $0x850F00, %%edi\n" // flags = VM|FS|FILES|SIGH|THR|SYSVSEM|UNTRCD
      "xor  %%rsi, %%rsi\n"     // stack = NULL
      "xor  %%rdx, %%rdx\n"     // pid   = NULL
      "xor  %%r10, %%r10\n"     // ctid  = NULL
      "xor  %%r8, %%r8\n"       // tls   = NULL
      "mov  0xC0(%%rbp), %%r15\n"
      "cmp  %%rbx, (%%rbp)\n"
      "jne  22b\n"              // exit process
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   22b\n"              // exit process
      "jz   0b\n"               // invoke trustedThreadFnc()

      // Done creating trusted thread. We can now get ready to return to caller
      "mov  0(%%rsp), %%r13d\n" // %r13 = threadFd
      "add  $16, %%rsp\n"

      // Set up thread local storage with information on how to talk to
      // trusted thread and trusted process.
      // This system call can potentially be corrupted by untrusted threads,
      // but that's OK.
      "mov  $9, %%eax\n"        // NR_mmap
      "xor  %%rdi, %%rdi\n"     // start  = NULL
      "mov  $4096, %%esi\n"     // length = 4096
      "mov  $3, %%edx\n"        // prot   = PROT_READ | PROT_WRITE
      "mov  $0x22, %%r10\n"     // flags  = PRIVATE|ANONYMOUS
      "mov  $-1, %%r8\n"        // fd     = -1
      "xor  %%r9, %%r9\n"       // offset = 0
      "syscall\n"
      "cmp  $-1, %%rax\n"       // MAP_FAILED
      "jz   23b\n"              // exit thread, unlock global mutex
      "mov  %%rax, %%rsi\n"     // args   = mmap()
      "mov  $158, %%eax\n"      // NR_arch_prctl
      "mov  $0x1001, %%edi\n"   // option = ARCH_SET_GS
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  23b\n"              // exit thread, unlock global mutex
      "mov  %%rsi, %%gs:0\n"    // setTLSValue(TLS_MEM, mmap())
      "mov  %%r14, %%gs:8\n"    // setTLSValue(TLS_TID, tid)
      "mov  %%r13, %%gs:16\n"   // setTLSValue(TLS_THREAD_FD, threadFd)
      "mov  0xC0(%%rbp), %%rax\n"
      "mov  %%rax, %%gs:24\n"   // setTLSValue(TLS_PROCESS_FD, processFd)
      "mov  0xC8(%%rbp), %%rax\n"
      "mov  %%rax, %%gs:32\n"   // setTLSValue(TLS_CLONE_FD, cloneFd)

      // Check whether this is the initial thread, or a newly created one
      "pop  %%r15\n"
      "test %%r15, %%r15\n"
      "jne  31f\n"

      // Returning from clone() into the newly created thread is special. We
      // cannot unroll the stack, as we just set up a new stack for this
      // thread. We have to explicitly restore CPU registers to the values
      // that they had when the program originally called clone().
      "sub  $0x80, %%rsp\n"     // Redzone compensation
      "mov  0x40(%%rbp), %%rax\n"
      "push %%rax\n"
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
      "cmp  %%rbx, (%%rbp)\n"
      "jne  22b\n"              // exit process

      // Release global mutex
   "31:mov  syscall_mutex@GOTPCREL(%%rip), %%rdi\n"
      "lock; addl $0x80000000, (%%rdi)\n"
      "je   32f\n"
      "mov  $1, %%edx\n"
      "mov  %%rdx, %%rsi\n"     // FUTEX_WAKE
      "mov  $202, %%eax\n"      // NR_futex
      "syscall\n"

      // Release privileges by entering seccomp mode.
   "32:mov  $157, %%eax\n"      // NR_prctl
      "mov  $22, %%edi\n"       // PR_SET_SECCOMP
      "mov  $1, %%esi\n"
      "syscall\n"
      // TODO(markus): Paranoia. Add some error handling

      // Return to caller. We are in the new thread, now.
      "xor  %%rax, %%rax\n"
      "test %%r15, %%r15\n"

      // Returning to createTrustedThread()
      "jz   33f\n"
      "jmp  *%%r15\n"

      // Returning to the place where clone() had been called
   "33:pop  %%r15\n"
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
#else
// TODO(markus): implement
#endif
  "999:pop  %0\n"
      : "=g"(fnc));
  return fnc;
}

} // namespace
