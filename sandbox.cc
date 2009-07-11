#include "library.h"
#include "sandbox_impl.h"
#include "syscall_table.h"

//#include "valgrind/valgrind.h"
#define RUNNING_ON_VALGRIND 1 // TODO(markus): remove

namespace playground {

// Need enough space to allocate PATH_MAX strings on the stack
char                  Sandbox::stack_[8192];

Sandbox::ProtectedMap Sandbox::protectedMap_;
int                   Sandbox::pid_;
char*                 Sandbox::secureCradle_;

bool Sandbox::sendFd(int transport, int fd0, int fd1, void* buf, ssize_t len) {
  int fds[2], count                     = 0;
  if (fd0 >= 0) { fds[count++]          = fd0; }
  if (fd1 >= 0) { fds[count++]          = fd1; }
  if (!count) {
    return false;
  }
  char cmsg_buf[CMSG_SPACE(count*sizeof(int))];
  memset(cmsg_buf, 0, CMSG_SPACE(count*sizeof(int)));
  struct SysCalls::kernel_iovec  iov[2] = { { 0 } };
  struct SysCalls::kernel_msghdr msg    = { 0 };
  int dummy                             = 0;
  iov[0].iov_base                       = &dummy;
  iov[0].iov_len                        = sizeof(dummy);
  if (buf && len > 0) {
    iov[1].iov_base                     = buf;
    iov[1].iov_len                      = len;
  }
  msg.msg_iov                           = iov;
  msg.msg_iovlen                        = buf && len > 0 ? 2 : 1;
  msg.msg_control                       = &cmsg_buf;
  msg.msg_controllen                    = CMSG_LEN(count*sizeof(int));
  struct cmsghdr *cmsg                  = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level                      = SOL_SOCKET;
  cmsg->cmsg_type                       = SCM_RIGHTS;
  cmsg->cmsg_len                        = CMSG_LEN(count*sizeof(int));
  memcpy(CMSG_DATA(cmsg), fds, count*sizeof(int));
  SysCalls sys;
  return NOINTR_SYS(sys.sendmsg(transport, &msg, 0)) ==
      (ssize_t)sizeof(dummy) + (buf && len > 0 ? len : 0);
}

bool Sandbox::getFd(int transport, int* fd0, int* fd1, void* buf, ssize_t*len){
  int count                            = 0;
  int *err                             = NULL;
  if (fd0) {
    if (!count++) {
      err                              = fd0;
    }
    *fd0                               = -1;
  }
  if (fd1) {
    if (!count++) {
      err                              = fd1;
    }
    *fd1                               = -1;
  }
  if (!count) {
    return false;
  }
  char cmsg_buf[CMSG_SPACE(count*sizeof(int))];
  memset(cmsg_buf, 0, CMSG_SPACE(count*sizeof(int)));
  struct SysCalls::kernel_iovec iov[2] = { { 0 } };
  struct SysCalls::kernel_msghdr msg   = { 0 };
  iov[0].iov_base                      = err;
  iov[0].iov_len                       = sizeof(int);
  if (buf && len && *len > 0) {
    iov[1].iov_base                    = buf;
    iov[1].iov_len                     = *len;
  }
  msg.msg_iov                          = iov;
  msg.msg_iovlen                       = buf && len && *len > 0 ? 2 : 1;
  msg.msg_control                      = &cmsg_buf;
  msg.msg_controllen                   = CMSG_LEN(count*sizeof(int));
  SysCalls sys;
  int bytes = NOINTR_SYS(sys.recvmsg(transport, &msg, 0));
  if (bytes != (int)sizeof(int) + (buf && len && *len > 0 ? *len : 0)) {
    *err                               = bytes >= 0 ? 0 : -EBADF;
    return false;
  }
  if (*err) {
    // Caller sent an errno value instead of a file handle
    return false;
  }
  struct cmsghdr *cmsg               = CMSG_FIRSTHDR(&msg);
  if ((msg.msg_flags & (MSG_TRUNC|MSG_CTRUNC)) ||
      !cmsg                                    ||
      cmsg->cmsg_level != SOL_SOCKET           ||
      cmsg->cmsg_type  != SCM_RIGHTS           ||
      cmsg->cmsg_len   != CMSG_LEN(count*sizeof(int))) {
    *err                             = -EBADF;
    return false;
  }
  if (fd1) { *fd1 = ((int *)CMSG_DATA(cmsg))[--count]; }
  if (fd0) { *fd0 = ((int *)CMSG_DATA(cmsg))[--count]; }
  return true;
}

void Sandbox::createTrustedProcess(int* fds, char* mem) {
  // Create a trusted process that can evaluate system call parameters and
  // decide whether a system call should execute. This process runs outside of
  // the seccomp sandbox. It communicates with the sandbox'd process through
  // a socketpair() and through securely shared memory.
  SysCalls sys;
  pid_t tid = sys.gettid();
  pid_t pid = fork();
  if (pid < 0) {
    die("Failed to create trusted process");
  }
  if (!pid) {
    NOINTR_SYS(sys.close(fds[0])); // processFd
    NOINTR_SYS(sys.close(fds[2])); // cloneFd
    trustedProcess(ChildArgs::pushArgs(stack_, mem,
                                       fds[4], // public side of threadFd
                                       fds[5], // process's side of threadFd
                                       fds[1], // process's side of processFd
                                       fds[2], // thread's side of cloneFd
                                       fds[3], // process's side of cloneFd
                                       tid));
    die();
  }

  NOINTR_SYS(sys.close(fds[1])); // process's side of processFd
  NOINTR_SYS(sys.close(fds[3])); // process's side of cloneFd
}

void Sandbox::createTrustedThread(int* fds, char* mem) {
  // Create a trusted thread that runs outside of the seccomp sandbox. This
  // code cannot trust any memory, and thus might have to forward requests to
  // the trusted process.
  // TODO(markus): rewrite in assembly so that we don't need to use the stack
  SysCalls sys;
  pid_t tid = sys.gettid();
  // TODO(markus): Make sure that freeTLS() will be called when thread dies
  TLS::allocateTLS();
  TLS::setTLSValue(TLS_TID,        tid);
  TLS::setTLSValue(TLS_THREAD_FD,  fds[4]);
  TLS::setTLSValue(TLS_PROCESS_FD, fds[0]);
  TLS::setTLSValue(TLS_CLONE_FD,   fds[2]);
  if (RUNNING_ON_VALGRIND) { // TODO(markus): remove
    // TODO(markus): pthread_create() is almost certainly the wrong way to do
    // this. But it makes valgrind happy. So, leave it as an option for now.
    pthread_t p;
    if (::pthread_create(&p, NULL, (void *(*)(void *))trustedThread,
                        ChildArgs::pushArgs(stack_, mem,
                                            fds[5],// thread's side of threadFd
                                            fds[0],// public side of processFd
                                            fds[2],// public side of cloneFd
                                            -1, -1,
                                            tid))) {
   failed:
      die("Failed to create trusted thread");
    }
  } else {
    ChildArgs *args;
    // TODO(markus): Cannot use stack_
    if (!(args = ChildArgs::pushArgs(stack_, mem,
                                     fds[5], // thread's side of threadFd
                                     fds[0], // public side of processFd
                                     fds[2], // public side of cloneFd
                                     -1, -1,
                                     tid)) ||
        sys.clone((int (*)(void *))trustedThread, args,
                  CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_UNTRACED|
                  CLONE_VM|CLONE_THREAD|CLONE_SYSVSEM, args, 0, 0, 0) <= 0) {
      goto failed;
    }
  }
}

void Sandbox::snapshotMemoryMappings(int processFd) {
  SysCalls sys;
  int fd = sys.open("/proc/self/maps", O_RDONLY, 0);
  if (fd < 0 || !sendFd(processFd, fd)) {
 failure:
    die("Cannot access /proc/self/maps");
  }
  NOINTR_SYS(sys.close(fd));
  int dummy;
  if (read(sys, processFd, &dummy, sizeof(dummy)) != sizeof(dummy)) {
    goto failure;
  }
}

void startSandbox() {
  Sandbox::startSandbox();
}

void Sandbox::startSandbox() {
  SysCalls sys;
  char* secure = (char *)mmap(0, 3*4096, PROT_NONE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  if (secure == MAP_FAILED) {
    die("Cannot initialize secure memory");
  }
  secureCradle_ = secure + 4096;

  pid_ = sys.getpid();

  // Must create process before thread, as they use the same virtual address
  // for the stack.
  char* mem = (char *)mmap(0, 4096, PROT_READ|PROT_WRITE,
                           MAP_SHARED|MAP_ANONYMOUS, -1,0);
  #if __WORDSIZE == 64
  // B8 E7 00 00 00     MOV $231, %eax
  // BF 01 00 00 00   0:MOV $1, %edi
  // 0F 05              SYSCALL
  // B8 3C 00 00 00     MOV $60, %eax
  // EB F2              JMP 0b
  memcpy(mem,
         "\xB8\xE7\x00\x00\x00\xBF\x01\x00"
         "\x00\x00\x0F\x05\xB8\x3C\x00\x00"
         "\x00\xEB\xF2", 19);
  #else
  // B8 FC 00 00 00     MOV    $252, %eax
  // BB 01 00 00 00   0:MOV    $1, %ebx
  // CD 80              INT    $0x80
  // B8 01 00 00 00     MOV    $1, %eax
  // EB F2              JMP    0b
  memcpy(mem,
         "\xB8\xFC\x00\x00\x00\xBB\x01\x00"
         "\x00\x00\xCD\x80\xB8\x01\x00\x00"
         "\x00\xEB\xF2", 19);
  #endif
  mprotect(mem, 4096, PROT_READ|PROT_EXEC);
  int pairs[4];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pairs  ) ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, pairs+2) ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, pairs+4)) {
    die("Failed to create trusted helpers");
  }
  createTrustedProcess(pairs, mem);
  createTrustedThread(pairs, mem);

  // Find all libraries that have system calls and redirect the system calls
  // to the sandbox. If we miss any system calls, the application will be
  // terminated by the kernel's seccomp code.
  {
    Maps maps("/proc/self/maps");
    const char *system_calls[] = {
      // TODO(markus): Make sure, this list includes all the system calls that
      // we care about.
      "brk", "close", "exit_group", "fcntl", "fstat", "futex", "getdents",
      "ioctl", "mmap", "munmap", "open", "stat", "clock_gettime",
      "__kernel_vsyscall", "__kernel_sigreturn", "__kernel_rt_sigreturn",
      "__vdso_clock_gettime", "__vdso_getcpu", "__vdso_gettimeofday",
      NULL
    };

    // Intercept system calls in libc, libpthread, and any other library that
    // might be interposed.
    for (Maps::const_iterator iter = maps.begin(); iter != maps.end(); ++iter){
      Library* library = *iter;
      library->makeWritable(true);
      for (const char **ptr = system_calls; *ptr; ptr++) {
        void *sym = library->getSymbol(*ptr);
        if (sym != NULL) {
          std::cout << "Found symbol: " << *ptr << std::endl;
          library->patchSystemCalls(syscallTable, maxSyscall,
                                    defaultSystemCallHandler);
          break;
        }
      }
      library->makeWritable(false);
    }
  }

  // Take a snapshot of the current memory mappings. These mappings will be
  // off-limit to all future mmap(), munmap(), mremap(), and mprotect() calls.
  snapshotMemoryMappings(pairs[0]);

#if 0 // TODO(markus): for debugging only
  if (sys.prctl(PR_GET_SECCOMP, 0) != 0) {
    die("Failed to enable Seccomp mode");
  }
  sys.prctl(PR_SET_SECCOMP, 1);
#else
  write(sys, 2, "WARNING! Seccomp mode is not enabled in this binary\n\n", 53);
#endif
}

} // namespace
