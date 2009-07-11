#include "sandbox_impl.h"
#include "securemem.h"

namespace playground {

// TODO(markus): Should this code be in clone.cc?
char* SecureMem::generateSecureMemSnippet(char* mem, ssize_t space,
                                          int cloneFd, int flags, void* stack,
                                          int* pid, int* ctid, void* tls,
                                          void(*trustedThread)(void *)) {
  struct {
    char*  start;                                  //  0
    char*  end;                                    //  1
    char*  fileName;                               //  2
    int*   flags;                                  //  3
    void** stack;                                  //  4
    int**  pid;                                    //  5
    int**  ctid;                                   //  6
    void** tls;                                    //  7
    char** secure;                                 //  8
    int*   cloneFd;                                //  9
    bool(**sendFd)(int, int, int, void*, ssize_t); // 10
    void(**trustedThread)();                       // 11
  } templ;
  __asm__ __volatile__(
    // TODO(markus): Avoid all memory and stack accesses
    #if __WORDSIZE == 64
      "lea  0f(%%rip), %%rax\n"
      "mov  %%rax, 0(%0)\n"  // start
      "lea  1f+1(%%rip), %%rax\n"
      "mov  %%rax, 24(%0)\n" // flags
      "lea  1f+7(%%rip), %%rax\n"
      "mov  %%rax, 32(%0)\n" // stack
      "lea  1f+17(%%rip), %%rax\n"
      "mov  %%rax, 40(%0)\n" // pid
      "lea  1f+27(%%rip), %%rax\n"
      "mov  %%rax, 48(%0)\n" // ctid
      "lea  1f+37(%%rip), %%rax\n"
      "mov  %%rax, 56(%0)\n" // tls
      "lea  6f+2(%%rip), %%rax\n"
      "mov  %%rax, 64(%0)\n" // secure
      "lea  7f+1(%%rip), %%rax\n"
      "mov  %%rax, 72(%0)\n" // cloneFd
      "lea  8f+2(%%rip), %%rax\n"
      "mov  %%rax, 80(%0)\n" // sendFd
      "lea  11f+2(%%rip), %%rax\n"
      "mov  %%rax, 88(%0)\n" // trustedThread
      "lea  100f(%%rip), %%rax\n"
      "mov  %%rax, 16(%0)\n" // fileName
      "lea  999f(%%rip), %%rax\n"
      "mov  %%rax, 8(%0)\n"  // end
      "jmp  999f\n"
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
      "jne  999f\n"

      // Nascent thread creates socketpair() for sending requests to
      // trusted thread.
      // We can create the filehandles on the stack. Filehandles are
      // always treated as untrusted.
      // socketpair(AF_UNIX, SOCK_STREAM, 0, fds)
      "mov  $53, %%eax\n"   // NR_socketpair
      "mov  $1, %%edi\n"    // domain = AF_UNIX
      "mov  $1, %%esi\n"    // type = SOCK_STREAM
      "xor  %%rdx, %%rdx\n" // protocol = 0
      "pushq %%rdx\n"       // used for futex()
      "sub  $8, %%rsp\n"    // sv = %rsp
      "mov  %%rsp, %%r10\n"
      "syscall\n"
      "test %%rax, %%rax\n"
      "jz   5f\n"

      // If things went wrong, we don't have an (easy) way of signaling
      // the parent. For our purposes, it is sufficient to fail with a
      // fatal error.
    "2:mov  $231, %%eax\n" // NR_exit_group
    "3:mov  $1, %%edi\n"   // status = 1
      "syscall\n"
    "4:mov  $60, %%eax\n"  // NR_exit
      "jmp  3b\n"

      // Get thread id of newly created thread
    "5:mov  $186, %%eax\n" // NR_gettid
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
      "jnz  9f\n"

      // Temporary thread tries to exclusively create file for file
      // name that it has received in the write-protected snippet.
      // open("/dev/shm/.sandboxXXXXXX", O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600)
      "mov  $2, %%eax\n"         // NR_open
      "lea  100f(%%rip), %%rdi\n"// pathname = "/dev/shm/.sandboxXXXXXX"
      "mov  $0x200C2, %%esi\n"   // flags    = O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW
      "mov  $0600, %%rdx\n"      // mode     = 0600
      "syscall\n"

      // If open() fails, exit.
      "test %%rax, %%rax\n"
      "js   4b\n"
      "mov  %%rax, %%r12\n"

      // Unlink file.
      // unlink("/dev/shm/.sandboxXXXXXX")
      "mov  $87, %%eax\n" // NR_unlink
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
      "mov  $77, %%eax\n"   // NR_ftruncate
      "mov  %%r12, %%rdi\n" // fd
      "mov  $4096, %%esi\n" // length = 4096
      "syscall\n"
      "test %%rax, %%rax\n"
      "jnz  4b\n"

      // Call mmap() to create shared memory in a well-known
      // location. This location must have guard pages on both
      // sides. As there is only one such well-known location, the
      // trusted process has to ensure that only one clone() request
      // is pending at any given time.
      // mmap(Sandbox::secure(), PROT_READ|PROT_EXEC,MAP_SHARED|MAP_FIXED,fd,0)
      "mov  $9, %%eax\n"                  // NR_mmap
    "6:mov  $0x1234567812345678, %%rdi\n" // start  = Sandbox::secure()
      "mov  $5, %%edx\n"                  // prot   = PROT_READ | PROT_EXEC
      "mov  $17, %%r10\n"                 // flags  = MAP_SHARED | MAP_FIXED
      "mov  %%r12, %%r8\n"                // fd
      "xor  %%r9, %%r9\n"                 // offset = 0
      "syscall\n"
      "cmp  %%rax, %%rdi\n"
      "jnz  4b\n"

      // Call fork() to unshare the address space then exit the
      // temporary thread.
      "mov  $57, %%eax\n" // NR_fork
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
    "7:mov  $0x12345678, %%edi\n" // transport = Sandbox::cloneFd()
      "mov  %%r12, %%rsi\n"       // fd0       = fd
      "movl 0(%%rsp), %%edx\n"    // fd1       = %rsp[0]
      "push %%r14\n"
      "mov  %%rsp, %%rcx\n"       // buf       = &tid
      "mov  $4, %%r8\n"           // len       = sizeof(int)
    "8:movq $0x1234567812345678, %%rax\n"
      "call *%%rax\n"             // Sandbox::sendFd()
      "jmp  4b\n"

      // Nascent thread calls futex().
      // futex(&tid, FUTEX_WAIT, tid, NULL)
    "9:cmpl %%eax, 8(%%rsp)\n"
      "jnz  10f\n"
      "lea  8(%%rsp), %%rdi\n" // uaddr
      "xor  %%rsi, %%rsi\n"    // op      = FUTEX_WAIT
      "mov  %%rax, %%rdx\n"    // val     = tid
      "xor  %%r10, %%r10\n"    // timeout = NULL
      "mov  $202, %%rax\n"     // NR_futex
      "syscall\n"
    "10:"

      // Trusted thread returns from futex() and tries to mremap()
      // shared memory from its original fixed location. It can do
      // this by temporarily increasing the size of the mapping
      "mov  $25, %%eax\n"         // NR_mremap
      "movq 6b+2(%%rip), %%rdi\n" // old_address = Sandbox::secure()
      "mov  $4096, %%esi\n"       // old_size    = 4096
      "mov  $8192, %%edx\n"       // new_size    = 8192
      "mov  $1, %%r10\n"          // flags       = MREMAP_MAYMOVE
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  2b\n"                     // TODO(markus): better error handling
      "mov  %%rax, %%rdi\n"           // old_address = tmp_address
      "mov  $25, %%eax\n"             // NR_mremap
      "mov  $8192, %%esi\n"           // old_size    = 8192
      "mov  $4096, %%edx\n"           // new_size    = 4096
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  2b\n"                 // TODO(markus): better error handling
      "mov  %%rax, %%r12\n"       // %r12   = secure_mem
      "mov  $9, %%eax\n"          // NR_mmap
      "movq 6b+2(%%rip), %%rdi\n" // start  = Sandbox::secure()
      "mov  $4096, %%esi\n"       // length = 4096
      "xor  %%rdx, %%rdx\n"       // prot   = PROT_NONE
      "mov  $0x32, %%r10\n"       // flags  = PRIVATE|FIXED|ANONYMOUS
      "mov  $-1, %%r8\n"          // fd     = -1
      "xor  %%r9, %%r9\n"         // offset = NULL
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
      "jnz  12f\n"
   "11:mov  $0x1234567812345678, %%rax\n"
      "jmp  *%%rax\n"
   "12:mov  0(%%rsp), %%r13d\n" // %r13 = threadFd
      "add  $16, %%rsp\n"

      // Set up thread local storage with information on how to talk to
      // trusted thread and trusted process.
      // This system call can potentially be corrupted by untrusted threads,
      // but that's OK.
      "mov  $9, %%eax\n"      // NR_mmap
      "xor  %%rdi, %%rdi\n"   // start  = NULL
      "mov  $4096, %%esi\n"   // length = 4096
      "mov  $3, %%edx\n"      // prot   = PROT_READ | PROT_WRITE
      "mov  $0x22, %%r10\n"   // flags  = PRIVATE|ANONYMOUS
      "mov  $-1, %%r8\n"      // fd     = -1
      "xor  %%r9, %%r9\n"     // offset = 0
      "syscall\n"
      "cmp  $-1, %%rax\n"     // MAP_FAILED
      "jz   4b\n"
      "mov  %%rax, %%rsi\n"   // args   = mmap()
      "mov  $158, %%eax\n"    // NR_arch_prctl
      "mov  $0x1001, %%edi\n" // option = ARCH_SET_GS
      "syscall\n"
      "cmp  $-4095, %%rax\n"
      "jae  4b\n"
      "mov  %%r14, %%gs:0\n"  // setTLSValue(TLS_TID, tid)
      "mov  %%r13, %%gs:8\n"  // setTLSValue(TLS_THREAD_FD, threadFd)
      "mov  %%r15, %%gs:16\n" // setTLSValue(TLS_PROCESS_FD, processFd)
      "mov  7b+1(%%rip), %%eax\n"
      "mov  %%rax, %%gs:24\n" // setTLSValue(TLS_CLONE_FD, cloneFd)

      // Release privileges by entering seccomp mode.
      "mov  $157, %%eax\n" // NR_prctl
      "mov  $22, %%edi\n"  // PR_SET_SECCOMP
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
      "100: .string \"/dev/shm/.sandboxXXXXXX\"\n"
      ".byte 0\n"
      "999:"
      :
      : "g"(&templ)
    #if __WORDSIZE == 64
      : "rax", "memory"
    #else
      : "eax", "memory"
    #endif
  );
  if (templ.end - templ.start > space) {
    Sandbox::die("Insufficient space for memory snippet");
  }

  // Copy template to destination buffer
  memcpy(mem, templ.start, templ.end - templ.start);

  // Enter parameters
  #define setArg(x, y)                                                        \
    (*(typeof templ.x)((char *)templ.x - templ.start + mem) = (y))
  setArg(flags,         flags);
  setArg(stack,         stack);
  setArg(pid,           pid);
  setArg(tls,           tls);
  setArg(ctid,          ctid);
  setArg(secure,        Sandbox::secureCradle());
  setArg(cloneFd,       cloneFd);
  setArg(sendFd,        &Sandbox::sendFd);
  setArg(trustedThread, Sandbox::getTrustedThreadFnc());
  #undef setArg

  // Generate unique filename. If this name turns out to not be unique, the
  // trusted thread will eventually notice and retry the operation.
  struct stat sb;
  char *fn = mem + (templ.fileName - templ.start);
  if (stat("/dev/shm/", &sb) || !S_ISDIR(sb.st_mode)) {
    strcpy(fn, "/tmp/.sandboxXXXXXX");
  }
  fn = strrchr(fn, '\000');
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned long long rnd = ((unsigned long long)tv.tv_usec << 16) & tv.tv_sec;
  unsigned long long r = rnd;
  for (int j = 0; j < 6; j++) {
    *--fn = 'A' + (r % 26);
    r /= 26;
  }

  // Return the next address where to output assembly code
  return mem + (templ.end - templ.start);
}

// TODO(markus): This code must be written in assembly. In fact just remove it. It's part of the trustedThread assembly code, already
unsigned long SecureMem::receiveSystemCallInternal(int err, char *mem) {
  if (err) {
    return err;
  } else {
    { char buf[80]; sprintf(buf, "Securely executing syscall %d\n", *(int *)(mem + (__WORDSIZE == 64 ? 1 : 3))); Sandbox::SysCalls sys; Sandbox::write(sys, 2, buf, strlen(buf)); } // TODO(markus): remove
    unsigned long rc;
    __asm__ __volatile__(
        "call *%1"
        : "=a"(rc)
        : "0"(mem)
      #if __WORDSIZE == 64
        : "rdi", "rsi", "rdx", "r10", "r8", "r9", "memory"
      #else
        : "ecx", "edx", "esi", "edi", "memory"
      #endif
        );
    return rc;
  }
}

void SecureMem::abandonSystemCall(int fd, int err) {
  int data[2] = { -1, err };
  if (err) write(2, "System call failed\n", 19); // TODO(markus): remove
  Sandbox::SysCalls sys;
  if (Sandbox::write(sys, fd, data, sizeof(data)) != sizeof(data)) {
    Sandbox::die("Failed to send system call");
  }
}

void SecureMem::sendSystemCallInternal(int fd, char *mem, int syscall_num,
                                       void *arg1, void *arg2, void *arg3,
                                       void *arg4, void *arg5, void *arg6) {
  // There is a special-case version of this code in clone.cc. If you make
  // any changes in the code here, make sure you make the same changes in
  // clone.cc
  #if __WORDSIZE == 64
  // TODO(markus): Check whether there is a security issue with us not being
  // able to change the shared memory page atomically. In particular, by
  // writing to threadFd(), malicious code could persuade the trusted thread
  // to run the same system call multiple times. Maybe, include a serial
  // number that has to increment sequentially?
  // TODO(markus): This code is currently not thread-safe.
  // B8 .. .. .. ..                   MOV  $..., %eax
  // 48 BF .. .. .. .. .. .. .. ..    MOV  $..., %rdi
  // 48 BE .. .. .. .. .. .. .. ..    MOV  $..., %rsi
  // 48 BA .. .. .. .. .. .. .. ..    MOV  $..., %rdx
  // 49 BA .. .. .. .. .. .. .. ..    MOV  $..., %r10
  // 49 B8 .. .. .. .. .. .. .. ..    MOV  $..., %r8
  // 49 B9 .. .. .. .. .. .. .. ..    MOV  $..., %r9
  // 0F 05                            SYSCALL
  // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
  // FF E1                            JMP  *%rcx
  memcpy(mem,
         "\xB8\x00\x00\x00\x00"
         "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x0F\x05"
         "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
         "\xFF\xE1", 79);

  *reinterpret_cast<int   *>(mem +  1) = syscall_num;
  *reinterpret_cast<void **>(mem +  7) = arg1;
  *reinterpret_cast<void **>(mem + 17) = arg2;
  *reinterpret_cast<void **>(mem + 27) = arg3;
  *reinterpret_cast<void **>(mem + 37) = arg4;
  *reinterpret_cast<void **>(mem + 47) = arg5;
  *reinterpret_cast<void **>(mem + 57) = arg6;
  *reinterpret_cast<void **>(mem + 69) =
      (void*)Sandbox::getTrustedThreadReturnResult();
  #else
  // TODO(markus): it is not safe to store %ebp and %ebx on the stack
  // 55                               PUSH %ebp
  // 53                               PUSH %ebx
  // B8 .. .. .. ..                   MOV  $..., %eax
  // BB .. .. .. ..                   MOV  $..., %ebx
  // B9 .. .. .. ..                   MOV  $..., %ecx
  // BA .. .. .. ..                   MOV  $..., %edx
  // BE .. .. .. ..                   MOV  $..., %esi
  // BF .. .. .. ..                   MOV  $..., %edi
  // BD .. .. .. ..                   MOV  $..., %ebp
  // CD 80                            INT  $0x80
  // 5B                               POP  %ebx
  // 5D                               POP  %ebp
  // C3                               RET
  memcpy(mem,
         "\x55"
         "\x53"
         "\xB8\x00\x00\x00\x00"
         "\xBB\x00\x00\x00\x00"
         "\xB9\x00\x00\x00\x00"
         "\xBA\x00\x00\x00\x00"
         "\xBE\x00\x00\x00\x00"
         "\xBF\x00\x00\x00\x00"
         "\xBD\x00\x00\x00\x00"
         "\xCD\x80"
         "\x5B"
         "\x5D"
         "\xC3", 42);
  *reinterpret_cast<int   *>(mem +  3) = syscall_num;
  *reinterpret_cast<void **>(mem +  8) = arg1;
  *reinterpret_cast<void **>(mem + 13) = arg2;
  *reinterpret_cast<void **>(mem + 18) = arg3;
  *reinterpret_cast<void **>(mem + 23) = arg4;
  *reinterpret_cast<void **>(mem + 28) = arg5;
  *reinterpret_cast<void **>(mem + 33) = arg6;
  #endif
  abandonSystemCall(fd, 0);
}

} // namespace
