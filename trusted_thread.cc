#include <map>

#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

// TODO(markus): This should probably be in syscall.c (which might need renaming to syscall.cc)
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
      rc = sys.read((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_write:
      rc = sys.write((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_rt_sigreturn:
      write(sys, 2, "rt_sigreturn()\n", 15);
      rc = sys.rt_sigreturn((unsigned long)arg0);
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

char* Sandbox::generateSecureCloneSnippet(char* mem, ssize_t space,
                                          int cloneFd, int flags, void* stack,
                                          int* pid, int* ctid, void* tls) {
  struct {
    char*  start;                                  //  0
    char*  end;                                    //  1
    int*   flags;                                  //  2
    void** stack;                                  //  3
    int**  pid;                                    //  4
    int**  ctid;                                   //  5
    void** tls;                                    //  6
    void** arguments;                              //  7
  } templ;
  asm volatile(
    #if __WORDSIZE == 64
      "lea  0f(%%rip), %%rax\n"
      "mov  %%rax, 0(%0)\n"  // start
      "lea  999f(%%rip), %%rax\n"
      "mov  %%rax, 8(%0)\n"  // end
      "lea  1f+1(%%rip), %%rax\n"
      "mov  %%rax, 16(%0)\n" // flags
      "lea  1f+7(%%rip), %%rax\n"
      "mov  %%rax, 24(%0)\n" // stack
      "lea  1f+17(%%rip), %%rax\n"
      "mov  %%rax, 32(%0)\n" // pid
      "lea  1f+27(%%rip), %%rax\n"
      "mov  %%rax, 40(%0)\n" // ctid
      "lea  1f+37(%%rip), %%rax\n"
      "mov  %%rax, 48(%0)\n" // tls
      "lea  100f(%%rip), %%rax\n"
      "mov  %%rax, 56(%0)\n" // arguments
      "jmp  1000f\n"
    "0:"

      // Original trusted thread calls clone() to create new nascent
      // thread. This thread is (typically) fully privileged and shares all
      // resources with the caller (i.e. the previous trusted thread),
      // and by extension it shares all resources with the sandbox'd
      // threads.
      // clone(flags, stack, pid, tls, ctid)
      "mov  $56, %%eax\n"                 // NR_clone
    "1:mov  $0x12345678, %%edi\n"         // flags
      "mov  $0x1234567812345678, %%rsi\n" // stack
      "mov  $0x1234567812345678, %%rdx\n" // pid
      "mov  $0x1234567812345678, %%r10\n" // ctid
      "mov  $0x1234567812345678, %%r8\n"  // tls
      "syscall\n"
      "test %%rax, %%rax\n"
      "jne  1000f\n"

      // Nascent thread creates socketpair() for sending requests to
      // trusted thread.
      // We can create the filehandles on the stack. Filehandles are
      // always treated as untrusted.
      // socketpair(AF_UNIX, SOCK_STREAM, 0, fds)
      "lea  100f(%%rip), %%rbp\n" // rbp = &arguments
    "nascent_thread:"
      "mov  $53, %%eax\n"       // NR_socketpair
      "mov  $1, %%edi\n"        // domain = AF_UNIX
      "mov  $1, %%esi\n"        // type = SOCK_STREAM
      "xor  %%rdx, %%rdx\n"     // protocol = 0
      "pushq %%rdx\n"           // used for futex()
      "sub  $8, %%rsp\n"        // sv = %rsp
      "mov  %%rsp, %%r10\n"
      "syscall\n"
      "test %%rax, %%rax\n"
      "jz   5f\n"

      // If things went wrong, we don't have an (easy) way of signaling
      // the parent. For our purposes, it is sufficient to fail with a
      // fatal error.
    "2:mov  $231, %%eax\n"      // NR_exit_group
    "3:mov  $1, %%edi\n"        // status = 1
      "syscall\n"
    "4:mov  $60, %%eax\n"       // NR_exit
      "jmp  3b\n"

      // Get thread id of newly created thread
    "5:mov  $186, %%eax\n"      // NR_gettid
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
      "js   2b\n"
      "jnz  6f\n"

      // Temporary thread tries to exclusively create file for file
      // name that it has received in the write-protected snippet.
      // open("/dev/shm/.sandboxXXXXXX", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600)
      "mov  $2, %%eax\n"        // NR_open
      "lea  28(%%rbp), %%rdi\n" // pathname = "/dev/shm/.sandboxXXXXXX"
      "mov  $0x200C2, %%esi\n"  // flags    = O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW
      "mov  $0600, %%rdx\n"     // mode     = 0600
      "syscall\n"

      // If open() fails, exit. TODO(markus): add error handling
      "test %%rax, %%rax\n"
      "js   4b\n"
      "mov  %%rax, %%r12\n"     // %r12 = secureMemFd

      // Unlink file.
      // unlink("/dev/shm/.sandboxXXXXXX")
      "mov  $87, %%eax\n"       // NR_unlink
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  4b\n"

      // If open() succeeds, write known-safe contents to this file
      // (e.g.  a code snippet that exits the entire process). This
      // ensures that we cannot trick the trusted thread into
      // executing user-controlled code, if an attacker managed to
      // confuse the trusted process about the location of the shared
      // memory region.
      // write(fd, 2b, 5b-2b)
      "mov  $1, %%eax\n"        // NR_write
      "mov  %%r12, %%rdi\n"     // fd
      "lea  2b(%%rip), %%rsi\n" // buf
      "mov  $5b-2b, %%rdx\n"    // count
      "syscall\n"
      "cmp  %%rax, %%rdx\n"
      "jnz  4b\n"

      // Ensure that the file is at least one page long. This is necessary
      // in order to call mmap().
      "mov  $77, %%eax\n"       // NR_ftruncate
      "mov  %%r12, %%rdi\n"     // fd
      "mov  $4096, %%esi\n"     // length = 4096
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  4b\n"

      // Call mmap() to create shared memory in a well-known
      // location. This location must have guard pages on both
      // sides. As there is only one such well-known location, the
      // trusted process has to ensure that only one clone() request
      // is pending at any given time.
      // mmap(Sandbox::secure(), PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0)
      "mov  $9, %%eax\n"        // NR_mmap
      "mov  0(%%rbp), %%rdi\n"  // start  = Sandbox::secureCradle()
      "mov  $5, %%edx\n"        // prot   = PROT_READ | PROT_EXEC
      "mov  $17, %%r10\n"       // flags  = MAP_SHARED | MAP_FIXED
      "mov  %%r12, %%r8\n"      // fd
      "xor  %%r9, %%r9\n"       // offset = 0
      "syscall\n"
      "cmp  %%rax, %%rdi\n"
      "jnz  4b\n"

      // Call fork() to unshare the address space then exit the
      // temporary thread.
      "mov  $57, %%eax\n"       // NR_fork
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  4b\n"

      // The fork()'d process uses sendmsg() to send the file handle
      // for the shared memory region to the trusted process. It also
      // sends the file handle for talking to the trusted thread, and
      // the new pid. The new pid is used as cookie by the trusted
      // process to decide where to send responses, too. To simplify
      // the code, this should probably happen on a dedicated
      // socketpair().
      "mov  8(%%rbp), %%edi\n"  // transport = Sandbox::cloneFd()
      "mov  %%r12, %%rsi\n"     // fd0       = fd
      "movl 0(%%rsp), %%edx\n"  // fd1       = %rsp[0]
      "push %%r14\n"
      "mov  %%rsp, %%rcx\n"     // buf       = &tid
      "mov  $4, %%r8\n"         // len       = sizeof(int)
      "mov 12(%%rbp), %%rax\n"
      "call *%%rax\n"           // Sandbox::sendFd()
      "jmp  4b\n"

      // Nascent thread calls futex().
      // futex(&tid, FUTEX_WAIT, tid, NULL)
    "6:cmpl %%eax, 8(%%rsp)\n"
      "jnz  7f\n"
      "lea  8(%%rsp), %%rdi\n"  // uaddr
      "xor  %%rsi, %%rsi\n"     // op      = FUTEX_WAIT
      "mov  %%rax, %%rdx\n"     // val     = tid
      "xor  %%r10, %%r10\n"     // timeout = NULL
      "mov  $202, %%rax\n"      // NR_futex
      "syscall\n"
     "7:"

      // Trusted thread returns from futex() and tries to mremap()
      // shared memory from its original fixed location. It can do
      // this by temporarily increasing the size of the mapping
      "mov  $25, %%eax\n"       // NR_mremap
      "mov  0(%%rbp), %%rdi\n"  // old_address = Sandbox::secure()
      "mov  $4096, %%esi\n"     // old_size    = 4096
      "mov  $8192, %%edx\n"     // new_size    = 8192
      "mov  $1, %%r10\n"        // flags       = MREMAP_MAYMOVE
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  2b\n"               // TODO(markus): better error handling
      "mov  %%rax, %%rdi\n"     // old_address = tmp_address
      "mov  $25, %%eax\n"       // NR_mremap
      "mov  $8192, %%esi\n"     // old_size    = 8192
      "mov  $4096, %%edx\n"     // new_size    = 4096
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  2b\n"               // TODO(markus): better error handling
      "mov  %%rax, %%r12\n"     // %r12   = secure_mem
      "mov  $9, %%eax\n"        // NR_mmap
      "movq 0(%%rbp), %%rdi\n"  // start  = Sandbox::secureCradle()
      "mov  $4096, %%esi\n"     // length = 4096
      "xor  %%rdx, %%rdx\n"     // prot   = PROT_NONE
      "mov  $0x32, %%r10\n"     // flags  = PRIVATE|FIXED|ANONYMOUS
      "mov  $-1, %%r8\n"        // fd     = -1
      "xor  %%r9, %%r9\n"       // offset = NULL
      "syscall\n"
      "cmp  %%rax, %%rdi\n"
      "jne  2b\n"

      // Call clone() to create new trusted thread().
      "mov  4(%%rsp), %%r13d\n" // %r13  = threadFd
      "mov  $56, %%eax\n"       // NR_clone
      "mov  $0x850F00, %%edi\n" // flags = VM|FS|FILES|SIGH|THR|SYSVSEM|UNTRCD
      "xor  %%rsi, %%rsi\n"     // stack = NULL
      "xor  %%rdx, %%rdx\n"     // pid   = NULL
      "xor  %%r10, %%r10\n"     // ctid  = NULL
      "xor  %%r8, %%r8\n"       // tls   = NULL
      "syscall\n"
      "test %%rax, %%rax\n"
      "js   2b\n"
      "jnz  8f\n"
      "mov  20(%%rbp), %%rax\n" // call *Sandbox::getTrustedThreadFnc()
      "jmp  *%%rax\n"
    "8:mov  0(%%rsp), %%r13d\n" // %r13 = threadFd
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
      "jz   4b\n"
      "mov  %%rax, %%rsi\n"     // args   = mmap()
      "mov  $158, %%eax\n"      // NR_arch_prctl
      "mov  $0x1001, %%edi\n"   // option = ARCH_SET_GS
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  4b\n"
      "mov  %%rsi, %%gs:0\n"    // setTLSValue(TLS_MEM, mmap())
      "mov  %%r14, %%gs:8\n"    // setTLSValue(TLS_TID, tid)
      "mov  %%r13, %%gs:16\n"   // setTLSValue(TLS_THREAD_FD, threadFd)
      "mov  %%r15, %%gs:24\n"   // setTLSValue(TLS_PROCESS_FD, processFd)
      "mov  8(%%rbp), %%eax\n"
      "mov  %%rax, %%gs:32\n"   // setTLSValue(TLS_CLONE_FD, cloneFd)

      // Release privileges by entering seccomp mode.
      "mov  $157, %%eax\n"      // NR_prctl
      "mov  $22, %%edi\n"       // PR_SET_SECCOMP
      "mov  $1, %%esi\n"
      "syscall\n"
      // TODO(markus): Paranoia. Add some error handling
      "xor  %%rax, %%rax\n"
      "jmp  999f\n"
    #else
      "lea  0f, %%eax\n"
      "mov  %%eax, 0(%0)\n"
      // TODO(markus): Add missing patch locations
      "lea  100f, %%eax\n"
      "mov  %%eax, 8(%0)\n"
      "lea  999f, %%eax\n"
      "mov  %%eax, 4(%0)\n"
      "push %%eax\n"
      "ret\n"
      "0:"
      // TODO(markus): Add missing code
      "nop\n"
    #endif
  "100:.byte 0, 0, 0, 0, 0, 0, 0, 0\n" // Sandbox::secureCradle()
      ".byte 0, 0, 0, 0\n"             // cloneFd
      ".byte 0, 0, 0, 0, 0, 0, 0, 0\n" // &Sandbox::sendFd()
      ".byte 0, 0, 0, 0, 0, 0, 0, 0\n" // Sandbox::getTrustedThreadFnc()
      ".string \"/dev/shm/.sandboxXXXXXX\"\n"
      ".byte 0xCC, 0xCC, 0xCC, 0xCC\n"
  "999:ret\n"
 "1000:"
      :
      : "g"(&templ)
    #if __WORDSIZE == 64
      : "rax", "memory"
    #else
      : "eax", "memory"
    #endif
  );
  if (templ.end - templ.start > space) {
    die("Insufficient space for memory snippet");
  }

  // Copy template to destination buffer
  memcpy(mem, templ.start, templ.end - templ.start);

  // Enter parameters for call to clone()
  #define setParm(x, y)                                                       \
    (*(typeof templ.x)((char *)templ.x - templ.start + mem) = (y))
  setParm(flags,         flags);
  setParm(stack,         stack);
  setParm(pid,           pid);
  setParm(tls,           tls);
  setParm(ctid,          ctid);
  #undef setParm

  // Set up argument area
  const int offSecure        = 0;
  const int offCloneFd       = offSecure        + sizeof(void *);
  const int offSendFdFnc     = offCloneFd       + sizeof(int);
  const int offTrustedThrFnc = offSendFdFnc     + sizeof(void *);
  const int offFilename      = offTrustedThrFnc + sizeof(void *);
  #define setArg(x, y)                                                        \
    (*(typeof(y) *)((char *)templ.arguments + (x) - templ.start + mem) = (y))
  setArg(offSecure,        secureCradle());
  setArg(offCloneFd,       cloneFd);
  setArg(offSendFdFnc,     &sendFd);
  setArg(offTrustedThrFnc, getTrustedThreadFnc());
  #undef setArg

  // Generate unique filename. If this name turns out to not be unique, the
  // trusted thread will eventually notice and retry the operation.
  // TODO(markus): implement this feature
  randomizedFilename(mem +
                     ((char *)templ.arguments + offFilename - templ.start));

  // Return the next address where to output assembly code
  return mem + (templ.end - templ.start);
}

void Sandbox::createTrustedThread(int processFd, int cloneFd) {
#if __WORDSIZE == 64
  register int processFd_ asm("r15") = processFd;
#endif
  struct {
    void* secureCradle;
    int   cloneFd;
    bool  (*sendFd)(int, int, int, void*, ssize_t);
    void  (*trustedThread)();
    char  filename[24];
  } __attribute__((packed)) args = {
    secureCradle(), cloneFd, &sendFd, getTrustedThreadFnc()
  };
  randomizedFilename(args.filename);
  asm volatile(
#if __WORDSIZE == 64
      "push %%rbx\n"
      "push %%rbp\n"
      "mov  %0, %%rbp\n"
      "call nascent_thread\n"
      "pop  %%rbp\n"
      "pop  %%rbx\n"
      :
      : "g"(&args), "g"(processFd_)
      : "rax", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12",
        "r13", "r14"
#else
// TODO(markus): implement
        "nop"
      :
      : "g"(&args)
#endif
);
}

void (*Sandbox::getTrustedThreadReturnResult())(void *) {
  void (*fnc)(void *);
  asm volatile(
#if __WORDSIZE == 64
      "lea trustedThreadReturnResult(%%rip), %0"
#else
      "nop\n"
// TODO(markus): Enable for 32bit
#endif
      : "=q"(fnc));
  return fnc;
}

void (*Sandbox::getTrustedThreadExitFnc())() {
  void (*fnc)();
  asm volatile(
#if __WORDSIZE == 64
      "lea trustedThreadExit(%%rip), %0"
#else
      "nop\n"
// TODO(markus): Enable for 32bit
#endif
      : "=q"(fnc));
  return fnc;
}

void (*Sandbox::getTrustedThreadFnc())() {
  void (*fnc)();
  asm volatile(
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

    "1:mov  $1, %%edi\n"    // status = 1
    "2:mov  $60, %%eax\n"   // NR_exit
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

    "trustedThreadExit:"
      "mov   %%rbp, %%rdi\n" // start = &scratch
      "mov   $4096, %%esi\n" // length = 4096
      "mov   $11, %%eax\n"   // NR_unmap
      "syscall\n"
      "mov   %%r12, %%rdi\n" // start = secure_mem
      "mov   $4096, %%esi\n" // length = 4096
      "mov   $11, %%eax\n"   // NR_unmap
      "syscall\n"
      "mov   %%r13, %%rdi\n" // fd = threadFd
      "mov   $3, %%eax\n"    // NR_close
      "syscall\n"
      "mov   %%r14, %%rdi\n" // status = exit_code
   "11:mov   $60, %%eax\n"   // NR_exit
      "syscall\n"
      "jmp   11b\n"
#else
// TODO(markus): implement
#endif
  "999:pop  %0\n"
      : "=g"(fnc));
  return fnc;
}

} // namespace
