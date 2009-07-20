#include "library.h"
#include "sandbox_impl.h"
#include "syscall_table.h"

//#include "valgrind/valgrind.h"
#define RUNNING_ON_VALGRIND 1 // TODO(markus): remove

namespace playground {

int                   Sandbox::pid_;
Sandbox::mutex_t*     Sandbox::syscall_mutex_;
int                   Sandbox::processFdPub_;
Sandbox::ProtectedMap Sandbox::protectedMap_;

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

void Sandbox::snapshotMemoryMappings(int processFd) {
  SysCalls sys;
  int shmFd;
  syscall_mutex_ = reinterpret_cast<mutex_t*>(makeSharedMemory(&shmFd));
  int mapsFd = sys.open("/proc/self/maps", O_RDONLY, 0);
  if (mapsFd < 0 || !sendFd(processFd, mapsFd, shmFd, NULL, NULL)) {
 failure:
    die("Cannot access /proc/self/maps");
  }
  NOINTR_SYS(sys.close(shmFd));
  NOINTR_SYS(sys.close(mapsFd));
  int dummy;
  if (read(sys, processFd, &dummy, sizeof(dummy)) != sizeof(dummy)) {
    goto failure;
  }
}

void Sandbox::startSandbox() {
  SysCalls sys;

  // The pid is unchanged for the entire program, so we can retrieve it once
  // and store it in a global variable.
  pid_ = sys.getpid();

  // Get socketpair for talking to the trusted process
  int pair[2];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair)) {
    die("Failed to create trusted thread");
  }
  processFdPub_     = pair[0];
  void* secureMem   = createTrustedProcess(pair[0], pair[1]);

  // We find all libraries that have system calls and redirect the system
  // calls to the sandbox. If we miss any system calls, the application will be
  // terminated by the kernel's seccomp code. So, from a security point of
  // view, if this code fails to identify system calls, we are still behaving
  // correctly.
  {
    Maps maps("/proc/self/maps");
    const char *system_calls[] = {
      "brk", "close", "exit_group", "fcntl", "fstat", "futex", "getdents",
      "ioctl", "mmap", "munmap", "open", "stat", "clock_gettime",
      "__kernel_vsyscall", "__kernel_sigreturn", "__kernel_rt_sigreturn",
      "__vdso_clock_gettime", "__vdso_getcpu", "__vdso_gettimeofday",
      NULL
    };

    // Intercept system calls in libc, libpthread, librt, and any other
    // library that might be interposed.
    for (Maps::const_iterator iter = maps.begin(); iter != maps.end(); ++iter){
      Library* library = *iter;
      library->makeWritable(true);
      for (const char **ptr = system_calls; *ptr; ptr++) {
        void *sym = library->getSymbol(*ptr);
        if (sym != NULL) {
          library->patchSystemCalls();
          break;
        }
      }
      library->makeWritable(false);
    }
  }

  // Take a snapshot of the current memory mappings. These mappings will be
  // off-limits to all future mmap(), munmap(), mremap(), and mprotect() calls.
  snapshotMemoryMappings(processFdPub_);

  // Creating the trusted thread enables sandboxing
  createTrustedThread(processFdPub_, secureMem);
}

} // namespace
