#include "library.h"
#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

// Global variables
int                           Sandbox::pid_;
int                           Sandbox::processFdPub_;
int                           Sandbox::cloneFdPub_;
Sandbox::ProtectedMap         Sandbox::protectedMap_;
std::vector<SecureMem::Args*> Sandbox::secureMemPool_;


bool Sandbox::sendFd(int transport, int fd0, int fd1, const void* buf,
                     size_t len) {
  int fds[2], count                     = 0;
  if (fd0 >= 0) { fds[count++]          = fd0; }
  if (fd1 >= 0) { fds[count++]          = fd1; }
  if (!count) {
    return false;
  }
  char cmsg_buf[CMSG_SPACE(count*sizeof(int))];
  memset(cmsg_buf, 0, sizeof(cmsg_buf));
  struct SysCalls::kernel_iovec  iov[2] = { { 0 } };
  struct SysCalls::kernel_msghdr msg    = { 0 };
  int dummy                             = 0;
  iov[0].iov_base                       = &dummy;
  iov[0].iov_len                        = sizeof(dummy);
  if (buf && len > 0) {
    iov[1].iov_base                     = const_cast<void *>(buf);
    iov[1].iov_len                      = len;
  }
  msg.msg_iov                           = iov;
  msg.msg_iovlen                        = (buf && len > 0) ? 2 : 1;
  msg.msg_control                       = cmsg_buf;
  msg.msg_controllen                    = CMSG_LEN(count*sizeof(int));
  struct cmsghdr *cmsg                  = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level                      = SOL_SOCKET;
  cmsg->cmsg_type                       = SCM_RIGHTS;
  cmsg->cmsg_len                        = CMSG_LEN(count*sizeof(int));
  memcpy(CMSG_DATA(cmsg), fds, count*sizeof(int));
  SysCalls sys;
  return NOINTR_SYS(sys.sendmsg(transport, &msg, 0)) ==
      (ssize_t)(sizeof(dummy) + ((buf && len > 0) ? len : 0));
}

bool Sandbox::getFd(int transport, int* fd0, int* fd1, void* buf, size_t*len) {
  int count                            = 0;
  int *err                             = NULL;
  if (fd0) {
    count++;
    err                                = fd0;
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
  memset(cmsg_buf, 0, sizeof(cmsg_buf));
  struct SysCalls::kernel_iovec iov[2] = { { 0 } };
  struct SysCalls::kernel_msghdr msg   = { 0 };
  iov[0].iov_base                      = err;
  iov[0].iov_len                       = sizeof(int);
  if (buf && len && *len > 0) {
    iov[1].iov_base                    = buf;
    iov[1].iov_len                     = *len;
  }
  msg.msg_iov                          = iov;
  msg.msg_iovlen                       = (buf && len && *len > 0) ? 2 : 1;
  msg.msg_control                      = cmsg_buf;
  msg.msg_controllen                   = CMSG_LEN(count*sizeof(int));
  SysCalls sys;
  ssize_t bytes = NOINTR_SYS(sys.recvmsg(transport, &msg, 0));
  if (len) {
    *len                               = bytes > (int)sizeof(int) ?
                                           bytes - sizeof(int) : 0;
  }
  if (bytes != (ssize_t)(sizeof(int) + ((buf && len && *len > 0) ? *len : 0))){
    *err                               = bytes >= 0 ? 0 : -EBADF;
    return false;
  }
  if (*err) {
    // "err" is the first four bytes of the payload. If these are non-zero,
    // the sender on the other side of the socketpair sent us an errno value.
    // We don't expect to get any file handles in this case.
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

void Sandbox::setupSignalHandlers() {
  // Block signals in sandboxed threads
  SysCalls sys;
  SysCalls::kernel_sigset_t mask;
  memset(&mask, 0xFF, sizeof(mask));
  mask.sig[0]   &= ~((1 << (SIGSEGV - 1)) | (1 << (SIGINT  - 1)) |
                     (1 << (SIGTERM - 1)) | (1 << (SIGQUIT - 1)) |
                     (1 << (SIGHUP  - 1)) | (1 << (SIGABRT - 1)) |
                     (1 << (SIGCHLD - 1)));
  sys.sigprocmask(SIG_SETMASK, &mask, 0);

  // Set up SEGV handler for dealing with RDTSC instructions
  struct SysCalls::kernel_sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler_ = segv;
  sys.sigaction(SIGSEGV, &sa, NULL);
}

void Sandbox::segv(int signo) {
  // We need to patch the signal call frame so that sigreturn() sets the
  // appropriate registers upon returning.
  #if defined(__x86_64__)
  unsigned short **ip = reinterpret_cast<unsigned short **>(
                        reinterpret_cast<char *>(&signo) + 220);
  unsigned long  *eax = reinterpret_cast<unsigned long   *>(
                        reinterpret_cast<char *>(&signo) + 196);
  unsigned long  *edx = reinterpret_cast<unsigned long   *>(
                        reinterpret_cast<char *>(&signo) + 188);
  #elif defined(__i386__)
  unsigned short **ip = reinterpret_cast<unsigned short **>(&signo) + 15;
  unsigned long  *eax = reinterpret_cast<unsigned long   *>(&signo) + 12;
  unsigned long  *edx = reinterpret_cast<unsigned long   *>(&signo) + 10;
  #else
  #error Unsupported target platform
  #endif
  if (**ip == 0x310F /* RDTSC */) {
    SysCalls sys;
    write(sys, 2, "RDTSC\n", 6);
    int request       = -3;
    struct {
      unsigned eax;
      unsigned edx;
    } __attribute__((packed)) response;
    if (write(sys, threadFdPub(), &request, sizeof(request)) !=
        sizeof(request) ||
        read(sys, threadFdPub(), &response, sizeof(response)) !=
        sizeof(response)) {
      die("Failed to forward RDTSC request [sandbox]");
    }
    ++*ip;
    *eax              = response.eax;
    *edx              = response.edx;
    return;
  }
  _exit(1);
}

void Sandbox::snapshotMemoryMappings(int processFd) {
  SysCalls sys;
  int mapsFd = sys.open("/proc/self/maps", O_RDONLY, 0);
  if (mapsFd < 0 || !sendFd(processFd, mapsFd, -1, NULL, NULL)) {
 failure:
    die("Cannot access /proc/self/maps");
  }
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
  pid_                           = sys.getpid();

  // Block all signals, except for the RDTSC handler
  setupSignalHandlers();

  // Get socketpairs for talking to the trusted process
  int pair[4];
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, pair+2)) {
    die("Failed to create trusted thread");
  }
  processFdPub_                  = pair[0];
  cloneFdPub_                    = pair[2];
  SecureMemArgs::Args* secureMem = createTrustedProcess(pair[0], pair[1],
                                                        pair[2], pair[3]);

  // We find all libraries that have system calls and redirect the system
  // calls to the sandbox. If we miss any system calls, the application will be
  // terminated by the kernel's seccomp code. So, from a security point of
  // view, if this code fails to identify system calls, we are still behaving
  // correctly.
  {
    Maps maps("/proc/self/maps");
    const char *libs[] = { "libc", "librt", "libpthread", NULL };

    // Intercept system calls in libraries that are known to have them.
    for (Maps::const_iterator iter = maps.begin(); iter != maps.end(); ++iter){
      Library* library = *iter;
      library->makeWritable(true);
      if (library->isVDSO()) {
        library->patchSystemCalls();
      } else {
        for (const char **ptr = libs; *ptr; ptr++) {
          char *name = strstr(iter.name().c_str(), *ptr);
          if (name) {
            char ch = name[strlen(*ptr)];
            if (ch < 'A' || (ch > 'Z' && ch < 'a') || ch > 'z') {
              library->patchSystemCalls();
            }
          }
        }
      }
      library->makeWritable(false);
    }
  }

  // Take a snapshot of the current memory mappings. These mappings will be
  // off-limits to all future mmap(), munmap(), mremap(), and mprotect() calls.
  snapshotMemoryMappings(processFdPub_);

  // Creating the trusted thread enables sandboxing
  createTrustedThread(processFdPub_, cloneFdPub_, secureMem);
}

} // namespace
