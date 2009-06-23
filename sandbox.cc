#include "library.h"
#include "sandbox_impl.h"
#include "syscall_table.h"

#include "valgrind/valgrind.h"
//#define RUNNING_ON_VALGRIND 1
#define ALLOW_ALL 1 // TODO(markus): Remove

namespace playground {

// Need enough space to allocate PATH_MAX strings on the stack
char                  Sandbox::stack_[8192];

Sandbox::SysCalls     Sandbox::sys_;
SecureMem             Sandbox::secureMem_(4096);
Sandbox::ProtectedMap Sandbox::protectedMap_;
int                   Sandbox::threadFd_;
int                   Sandbox::processFd_;
int                   Sandbox::pid_;

bool Sandbox::sendFd(int transport, int fd) {
  char cmsg_buf[CMSG_SPACE(sizeof(int))] = { 0 };
  struct SysCalls::kernel_iovec  iov     = { 0 };
  struct SysCalls::kernel_msghdr msg     = { 0 };
  iov.iov_base            = &fd;
  iov.iov_len             = sizeof(fd);
  msg.msg_iov             = &iov;
  msg.msg_iovlen          = 1;
  msg.msg_control         = &cmsg_buf;
  msg.msg_controllen      = sizeof(cmsg_buf);
  struct cmsghdr *cmsg    = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level        = SOL_SOCKET;
  cmsg->cmsg_type         = SCM_RIGHTS;
  cmsg->cmsg_len          = CMSG_LEN(sizeof(fd));
  *(int *)CMSG_DATA(cmsg) = fd;
  return NOINTR_SYS(sys_.sendmsg(transport, &msg, 0)) == sizeof(fd);
}

int Sandbox::getFd(int transport) {
  char cmsg_buf[CMSG_SPACE(sizeof(int))] = { 0 };
  struct SysCalls::kernel_iovec iov      = { 0 };
  struct SysCalls::kernel_msghdr msg     = { 0 };
  int dummy;
  iov.iov_base       = &dummy;
  iov.iov_len        = sizeof(dummy);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = &cmsg_buf;
  msg.msg_controllen = sizeof(cmsg_buf);
  int bytes          = NOINTR_SYS(sys_.recvmsg(transport, &msg, 0));
  if (bytes != sizeof(dummy)) {
    if (bytes >= 0) {
      errno = EBADF;
    }
    return -1;
  }
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  if (!cmsg || cmsg->cmsg_level != SOL_SOCKET ||
      cmsg->cmsg_type != SCM_RIGHTS) {
    errno = EBADF;
    return -1;
  }
  return *(int *)CMSG_DATA(cmsg);
}

void* Sandbox::defaultSystemCallHandler(int syscallNum, void *arg0, void *arg1,
                                        void *arg2, void *arg3, void *arg4,
                                        void *arg5) {
  // TODO(markus): The following comment is currently not true, we do intercept these system calls. Try to fix that.

  // We try to avoid intercepting read(), write(), sigreturn(), and exit(), as
  // these system calls are not restricted in Seccomp mode. But depending on
  // the exact instruction sequence in libc, we might not be able to reliably
  // filter out these system calls at the time when we instrument the code.
  SysCalls sys;
  unsigned long rc;
  switch (syscallNum) {
    case __NR_read:
      write(2, "read()\n", 7);
      rc = sys.read((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_write:
      write(2, "write()\n", 8);
      rc = sys.write((long)arg0, arg1, (size_t)arg2);
      break;
    case __NR_rt_sigreturn:
      write(2, "rt_sigreturn()\n", 15);
      rc = sys.rt_sigreturn((unsigned long)arg0);
      break;
    case __NR_exit:
      write(2, "exit()\n", 7);
      rc = sys._exit((long)arg0);
      break;
    default:
      if (syscallNum == __NR_close && arg0 == (void *)2) return 0; // TODO(markus): remove
      if ((unsigned)syscallNum <= maxSyscall() &&
          (syscallTable[syscallNum].trustedThread == UNRESTRICTED_SYSCALL ||
           (ALLOW_ALL && !syscallTable[syscallNum].trustedThread /* TODO(markus): Temporary hack */))) {
        { char buf[80]; sprintf(buf, "Unrestricted syscall %d\n", syscallNum); write(2, buf, strlen(buf)); } // TODO(markus): remove
        struct {
          int          sysnum;
          Unrestricted unrestricted_req;
        } __attribute__((packed)) request = {
          syscallNum, { arg0, arg1, arg2, arg3, arg4, arg5 } };

        int   thread = threadFd();
        void* rc;
        if (write(thread, &request, sizeof(request)) != sizeof(request) ||
            read(thread, &rc, sizeof(rc)) != sizeof(rc)) {
          die("Failed to forward unrestricted system call");
        }
        return rc;
      } else {
        char buf[80] = { 0 };
        snprintf(buf, sizeof(buf)-1, "Uncaught system call %d\n", syscallNum);
        sys.write(2, buf, strlen(buf));
        return (void *)-EINVAL;
      }
  }
  if (rc < 0) {
    rc = -sys.my_errno;
  }
  return (void *)rc;
}

void Sandbox::trustedThread(void *args_) {
  // TODO(markus): The trusted thread is susceptible to race conditions as it
  // shares address space with the sandboxed process. It has to be written in
  // assembly to be secure. Most notably, it is not OK to use the stack for
  // things like return addresses, so any function calls are impossible in this
  // context. Similarly, we need to be careful when spilling temporary data
  // on the stack.
  // TODO(markus): Coalesce the read() operations by reading into a bigger
  // buffer.
  secureMem_.SetMode(SecureMem::SANDBOX);
  ChildArgs *args = reinterpret_cast<ChildArgs *>(args_);
  int fd = args->fd;
  for (;;) {
    unsigned int sysnum;
    int rc;
    if ((rc = Sandbox::read(fd, &sysnum, sizeof(sysnum)) != sizeof(sysnum))) {
      if (rc) {
        die("Failed to read system call number");
      }
      die();
    }
    if (sysnum == (unsigned int)-1) {
      // More complicated system calls talk to the trusted process, which
      // will send results back to the trusted thread. This looks like a
      // system call with number -1. We then execute the code in the
      // secure memory segment.
      void* rc = secureMem().receiveSystemCall<void *>(fd);

      // Return result
      if (write(fd, &rc, sizeof(rc)) != sizeof(rc)) {
        die("Failed to forward results from unrestricted system call");
      }
    } else {
      if (sysnum > maxSyscall() || (!ALLOW_ALL && !syscallTable[sysnum].trustedThread /* TODO(markus): Temporary hack */)) {
        die("Trusted process encountered unexpected system call");
      }
      void* handler = syscallTable[sysnum].trustedThread;
      if (handler == UNRESTRICTED_SYSCALL || (ALLOW_ALL && !handler /* TODO(markus): Temporary hack */)) {
        // Read request
        Unrestricted unrestricted_req;
        if (read(fd, &unrestricted_req, sizeof(unrestricted_req)) !=
            sizeof(unrestricted_req)) {
          die("Failed to read parameters for unrestricted system call");
        }

        // Perform request
        void* rc = sys_.syscall(sysnum, unrestricted_req.arg0,
                                unrestricted_req.arg1, unrestricted_req.arg2,
                                unrestricted_req.arg3, unrestricted_req.arg4,
                                unrestricted_req.arg5);

        // Return result
        if (write(fd, &rc, sizeof(rc)) != sizeof(rc)) {
          die("Failed to forward results from unrestricted system call");
        }
      } else {
        reinterpret_cast<void (*)(int)>(
            syscallTable[sysnum].trustedThread)(fd);
      }
    }
  }
}

void Sandbox::trustedProcess(void *args_) {
  // We share all resources with the sandboxed process, except for the address
  // space, the signal handlers, and file handles.

  // Set up securely shared memory
  secureMem_.SetMode(SecureMem::MONITOR);
  ChildArgs *args = reinterpret_cast<ChildArgs *>(args_);
  int fd = args->fd;

  // Read the memory mappings as they were before the sandbox takes effect.
  // These mappings cannot be changed by the sandboxed process.
  {
    int mapsFd;
    if ((mapsFd = getFd(fd)) < 0) {
   maps_failure:
      die("Cannot access /proc/self/maps");
    }
    char line[80];
    FILE *fp = fdopen(mapsFd, "r");
    for (bool truncated = false;;) {
      if (fgets(line, sizeof(line), fp) == NULL) {
        if (feof(fp) || errno != EINTR) {
          break;
        }
        continue;
      }
      if (!truncated) {
        unsigned long start, stop;
        char *ptr = line;
        errno = 0;
        start = strtoul(ptr, &ptr, 16);
        if (errno || *ptr++ != '-') {
       parse_failure:
          die("Failed to parse /proc/self/maps");
        }
        stop = strtoul(ptr, &ptr, 16);
        if (errno || *ptr++ != ' ') {
          goto parse_failure;
        }
        protectedMap_[reinterpret_cast<void *>(start)] = stop - start;
      }
      truncated = strchr(line, '\n') == NULL;
    }
    NOINTR_SYS(sys_.close(mapsFd));
    if (Sandbox::write(fd, &mapsFd, sizeof(mapsFd)) != sizeof(mapsFd)) {
      goto maps_failure;
    }
  }

  // Dispatch system calls that have been forwarded from the trusted thread.
  for (;;) {
    unsigned int sysnum;
    int rc;
    if ((rc = Sandbox::read(fd, &sysnum, sizeof(sysnum)) != sizeof(sysnum))) {
      if (rc) {
        die("Failed to read system call number");
      }
      die();
    }
    if (sysnum > maxSyscall() || !syscallTable[sysnum].trustedProcess) {
      die("Trusted process encountered unexpected system call");
    }
    syscallTable[sysnum].trustedProcess(fd);
  }
}

void Sandbox::createTrustedProcess(int fd, int closeFd) {
  // Create a trusted process that can evaluate system call parameters and
  // decide whether a system call should execute. This process runs outside of
  // the seccomp sandbox. It communicates with the sandbox'd process through
  // a socketpair() and through securely shared memory.
  pid_t pid = fork();
  if (pid < 0) {
    die("Failed to create trusted process");
  }
  if (!pid) {
    NOINTR_SYS(sys_.close(closeFd));
    trustedProcess(ChildArgs::pushArgs(stack_, fd));
    die();
  }

  NOINTR_SYS(sys_.close(fd));
}

void Sandbox::createTrustedThread(int fd) {
  // Create a trusted thread that runs outside of the seccomp sandbox. This
  // code cannot trust any memory, and thus might have to forward requests to
  // the trusted process.
  // TODO(markus): rewrite in assembly so that we don't need to use the stack
  if (RUNNING_ON_VALGRIND) { // TODO(markus): remove
    // TODO(markus): pthread_create() is almost certainly the wrong way to do
    // this. But it makes valgrind happy. So, leave it as an option for now.
    pthread_t p;
    if (::pthread_create(&p, NULL, (void *(*)(void *))trustedThread,
                         ChildArgs::pushArgs(stack_, fd))) {
   failed:
      die("Failed to create trusted thread");
    }
  } else {
    ChildArgs *args;
    if (!(args = ChildArgs::pushArgs(stack_, fd)) ||
        sys_.clone((int (*)(void *))trustedThread, args,
                   CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_UNTRACED|
                   CLONE_VM|CLONE_THREAD|CLONE_SYSVSEM, args, 0, 0, 0) <= 0) {
      goto failed;
    }
  }
}

void Sandbox::snapshotMemoryMappings() {
  int fd = sys_.open("/proc/self/maps", O_RDONLY, 0);
  if (fd < 0 || !sendFd(processFd_, fd)) {
 failure:
    die("Cannot access /proc/self/maps");
  }
  NOINTR_SYS(sys_.close(fd));
  int dummy;
  if (Sandbox::read(processFd_, &dummy, sizeof(dummy)) != sizeof(dummy)) {
    goto failure;
  }
}

void startSandbox() {
  Sandbox::startSandbox();
}

void Sandbox::startSandbox() {
  // TODO(markus): Find work-around for kernels that can escape the seccomp
  // sandbox by switching addressing modes.

  pid_ = sys_.getpid();

  // Must create process before thread, as they use the same virtual address
  // for the stack.
  int pair[4];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair  ) ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, pair+2)) {
    die("Failed to create trusted helpers");
  }
  processFd_ = pair[0];
  threadFd_  = pair[2];
  createTrustedProcess(pair[1], pair[3]);
  createTrustedThread(pair[3]);

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
          library->patchSystemCalls(syscallTable, maxSyscall(),
                                    defaultSystemCallHandler);
          break;
        }
      }
      library->makeWritable(false);
    }
  }

  // Take a snapshot of the current memory mappings. These mappings will be
  // off-limit to all future mmap(), munmap(), mremap(), and mprotect() calls.
  snapshotMemoryMappings();

#if 1 // TODO(markus): for debugging only
  if (sys_.prctl(PR_GET_SECCOMP, 0) != 0) {
    die("Failed to enable Seccomp mode");
  }
  sys_.prctl(PR_SET_SECCOMP, 1);
#else
  write(2, "WARNING! Seccomp mode is not enabled in this binary\n\n", 53);
#endif
}

} // namespace
