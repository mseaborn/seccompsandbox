#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_stat(const char *path, void *buf) {
  SysCalls sys;
  write(sys, 2, "stat()\n", 7);
  struct {
    int       sysnum;
    Stat      stat_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_stat;
  request.stat_req.sysnum = __NR_stat;
  request.stat_req.path   = path;
  request.stat_req.buf    = reinterpret_cast<SysCalls::kernel_stat *>(buf);

  int rc[sizeof(void *)/sizeof(int)];
  int thread = threadFd();
  if (write(sys, thread, &request, sizeof(request)) != sizeof(request) ||
      read(sys, thread, rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward stat() request [sandbox]");
  }
  return rc[0];
}

#if __WORDSIZE == 32
int Sandbox::sandbox_stat64(const char *path, void *buf) {
  SysCalls sys;
  write(sys, 2, "stat64()\n", 9);
  struct {
    int       sysnum;
    Stat      stat_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_stat64;
  request.stat_req.sysnum = __NR_stat64;
  request.stat_req.path   = path;
  request.stat_req.buf    = reinterpret_cast<SysCalls::kernel_stat *>(buf);

  int rc[sizeof(void *)/sizeof(int)];
  int thread = threadFd();
  if (write(sys, thread, &request, sizeof(request)) != sizeof(request) ||
      read(sys, thread, rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward stat() request [sandbox]");
  }
  return rc[0];
}
#endif

void* Sandbox::thread_stat(int processFd, long long cookie, int threadFd,
                           SecureMem::Args* mem) {
  // Read request
  SysCalls sys;
  struct Request {
    int       sysnum;
    long long cookie;
    Stat      stat_req;
  } __attribute__((packed)) request;
  if (read(sys, threadFd, &request.stat_req, sizeof(request.stat_req)) !=
      sizeof(request.stat_req)) {
    die("Failed to read parameters for stat() [thread]");
  }
  request.sysnum = request.stat_req.sysnum;
  request.cookie = cookie;

  // Forward request to trusted process
  // TODO(markus): Must coalesce writes to avoid race conditions.
  // TODO(markus): Maybe, move this code into sandbox_stat()
  const char *pathname = request.stat_req.path;
  request.stat_req.path_length = strlen(pathname);
  int rc;
  #if __WORDSIZE == 64
  int len = sizeof(SysCalls::kernel_stat);
  #else
  int len = request.stat_req.sysnum == __NR_stat ?
      sizeof(SysCalls::kernel_stat) : sizeof(SysCalls::kernel_stat64);
  #endif
  if (write(sys, processFd, &request, sizeof(request)) != sizeof(request) ||
      write(sys, processFd, pathname, request.stat_req.path_length) !=
      request.stat_req.path_length ||
      read(sys, threadFd, &rc, sizeof(rc)) != sizeof(rc) ||
      read(sys, threadFd, request.stat_req.buf, len) != len) {
    die("Failed to forward stat() request [thread]");
  }

  // Return result
  return reinterpret_cast<void *>(rc);
}

bool Sandbox::process_stat(int sandboxFd, int threadFdPub, int threadFd,
                           SecureMem::Args* mem) {
  // Read request
  SysCalls sys;
  Stat stat_req;
  if (read(sys, sandboxFd, &stat_req, sizeof(stat_req)) != sizeof(stat_req)) {
 read_parm_failed:
    die("Failed to read parameters for stat() [process]");
  }
  int rc = -ENAMETOOLONG;
  if (stat_req.path_length > PATH_MAX) {
    char buf[32];
    while (stat_req.path_length > 0) {
      int i = read(sys, sandboxFd, buf, sizeof(buf));
      if (i <= 0) {
        goto read_parm_failed;
      }
      stat_req.path_length -= i;
    }
    if (write(sys, threadFdPub, &rc, sizeof(rc)) != sizeof(rc)) {
   failed_to_reply:
      die("Failed to return data from stat() [process]");
    }
    return false;
  }
  char path[stat_req.path_length + 1];
  if (read(sys, sandboxFd, path, stat_req.path_length) !=
      stat_req.path_length) {
    goto read_parm_failed;
  }
  path[stat_req.path_length] = '\000';

  // Stat file
  // TODO(markus): A better solution is to send the system call, but to
  //               store the filename in the secure memory page
  // TODO(markus): Implement sandboxing policy
  struct Response {
    int                       rc;
    union {
      SysCalls::kernel_stat   sb;
      SysCalls::kernel_stat64 sb64;
    };
  } __attribute__((packed)) response;
  int len = sizeof(int) + sizeof(SysCalls::kernel_stat);
  switch (stat_req.sysnum) {
    case __NR_stat:
      response.rc = sys.stat(path, &response.sb);
      break;
    #if __WORDSIZE == 32
    case __NR_stat64:
      len = sizeof(int) + sizeof(SysCalls::kernel_stat64);
      response.rc = sys.stat64(path, &response.sb64);
      break;
    #endif
    default:
      goto read_parm_failed;
  }
  // Return result back to trusted thread
  if (response.rc < 0) {
    response.rc              = -sys.my_errno;
  }
  if (write(sys, threadFdPub, &response, len) != len) {
    goto failed_to_reply;
  }
  return true;
}

} // namespace
