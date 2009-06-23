#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_stat(const char *path, void *buf) {
  write(2, "stat()\n", 7);
  struct {
    int sysnum;
    Stat stat_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_stat;
  request.stat_req.sysnum = __NR_stat;
  request.stat_req.path   = path;
  request.stat_req.buf    = reinterpret_cast<SysCalls::kernel_stat *>(buf);

  int rc, thread = threadFd();
  if (write(thread, &request, sizeof(request)) != sizeof(request) ||
      read(thread, &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward stat() request [sandbox]");
  }
  return rc;
}

#if __WORDSIZE == 32
int Sandbox::sandbox_stat64(const char *path, void *buf) {
  write(2, "stat64()\n", 9);
  struct {
    int sysnum;
    Stat stat_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_stat64;
  request.stat_req.sysnum = __NR_stat64;
  request.stat_req.path   = path;
  request.stat_req.buf    = reinterpret_cast<SysCalls::kernel_stat *>(buf);

  int rc, thread = threadFd();
  if (write(thread, &request, sizeof(request)) != sizeof(request) ||
      read(thread, &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward stat() request [sandbox]");
  }
  return rc;
}
#endif

void Sandbox::thread_stat(int fd) {
  // Read request
  struct Request {
    int sysnum;
    Stat stat_req;
  } __attribute__((packed)) request;
  if (read(fd, &request.stat_req, sizeof(request.stat_req)) !=
                 sizeof(request.stat_req)) {
    die("Failed to read parameters for stat() [thread]");
  }
  request.sysnum = request.stat_req.sysnum;

  // Forward request to trusted process
  const char *pathname = request.stat_req.path;
  request.stat_req.path_length = strlen(pathname);
  int rc, process = processFd();
  #if __WORDSIZE == 64
  int len = sizeof(SysCalls::kernel_stat);
  #else
  int len = request.stat_req.sysnum == __NR_stat ?
      sizeof(SysCalls::kernel_stat) : sizeof(SysCalls::kernel_stat64);
  #endif
  if (write(process, &request, sizeof(request)) != sizeof(request) ||
      write(process, pathname, request.stat_req.path_length) !=
      request.stat_req.path_length ||
      read(process, &rc, sizeof(rc)) != sizeof(rc) ||
      read(process, request.stat_req.buf, len) != len) {
 forward_failed:
    die("Failed to forward stat() request [thread]");
  }

  // Return result
  if (write(fd, &rc, sizeof(rc)) != sizeof(rc)) {
    goto forward_failed;
  }
}

void Sandbox::process_stat(int fd) {
  // Read request
  Stat stat_req;
  if (read(fd, &stat_req, sizeof(stat_req)) != sizeof(stat_req)) {
 read_parm_failed:
    die("Failed to read parameters for stat() [process]");
  }
  int rc = -ENAMETOOLONG;
  if (stat_req.path_length > PATH_MAX) {
    char buf[32];
    while (stat_req.path_length > 0) {
      int i = read(fd, buf, sizeof(buf));
      if (i <= 0) {
        goto read_parm_failed;
      }
      stat_req.path_length -= i;
    }
    if (write(fd, &rc, sizeof(rc)) != sizeof(rc)) {
   failed_to_reply:
      die("Failed to return data from stat() [process]");
    }
    return;
  }
  char path[stat_req.path_length + 1];
  if (read(fd, path, stat_req.path_length) != stat_req.path_length) {
    goto read_parm_failed;
  }
  path[stat_req.path_length] = '\000';

  // Stat file
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
      response.rc = sys_.stat(path, &response.sb);
      break;
    #if __WORDSIZE == 32
    case __NR_stat64:
      len = sizeof(int) + sizeof(SysCalls::kernel_stat64);
      response.rc = sys_.stat64(path, &response.sb64);
      break;
    #endif
    default:
      goto read_parm_failed;
  }
  // Return result back to trusted thread
  if (write(fd, &response, len) != len) {
    goto failed_to_reply;
  }
}

} // namespace

extern "C" {
int sandbox_stat(const char *path, void *buf)
  __attribute__((alias("_ZN10playground7Sandbox12sandbox_statEPKcPv")));
#if __WORDSIZE == 32
int sandbox_stat64(const char *path, void *buf)
  __attribute__((alias("_ZN10playground7Sandbox14sandbox_stat64EPKcPv")));
#endif
void thread_stat(int fd)
  __attribute__((alias("_ZN10playground7Sandbox11thread_statEi")));
void process_stat(int fd)
  __attribute__((alias("_ZN10playground7Sandbox12process_statEi")));
} // extern "C"
