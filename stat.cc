#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_stat(const char *path, void *buf) {
  SysCalls sys;
  write(sys, 2, "stat()\n", 7);
  int len                       = strlen(path);
  struct Request {
    int       sysnum;
    long long cookie;
    Stat      stat_req;
    char      pathname[0];
  } __attribute__((packed)) *request;
  char data[sizeof(struct Request) + len];
  request                       = reinterpret_cast<struct Request*>(data);
  request->sysnum               = __NR_stat;
  request->cookie               = cookie();
  request->sysnum               = __NR_stat;
  request->stat_req.path_length = len;
  request->stat_req.buf         = buf;
  memcpy(request->pathname, path, len);

  long rc;
  if (write(sys, processFdPub(), request, sizeof(data)) != (int)sizeof(data) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward stat() request [sandbox]");
  }
  return static_cast<int>(rc);
}

#if __WORDSIZE == 32
int Sandbox::sandbox_stat64(const char *path, void *buf) {
  SysCalls sys;
  write(sys, 2, "stat64()\n", 9);
  int len                       = strlen(path);
  struct Request {
    int       sysnum;
    long long cookie;
    Stat      stat_req;
    char      pathname[0];
  } __attribute__((packed)) *request;
  char data[sizeof(struct Request) + len];
  request                       = reinterpret_cast<struct Request*>(data);
  request->sysnum               = __NR_stat64;
  request->cookie               = cookie();
  request->sysnum               = __NR_stat64;
  request->stat_req.path_length = len;
  request->stat_req.buf         = buf;
  memcpy(request->pathname, path, len);

  long rc;
  if (write(sys, processFdPub(), request, sizeof(data)) != (int)sizeof(data) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward stat64() request [sandbox]");
  }
  return static_cast<int>(rc);
}
#endif

bool Sandbox::process_stat(int parentProc, int sandboxFd, int threadFdPub,
                           int threadFd, SecureMem::Args* mem) {
  // Read request
  SysCalls sys;
  Stat stat_req;
  if (read(sys, sandboxFd, &stat_req, sizeof(stat_req)) != sizeof(stat_req)) {
 read_parm_failed:
    die("Failed to read parameters for stat() [process]");
  }
  int   rc                  = -ENAMETOOLONG;
  char* pathname            = getSecureStringBuffer(stat_req.path_length);
  if (!pathname) {
    char buf[32];
    while (stat_req.path_length > 0) {
      int i = read(sys, sandboxFd, buf, sizeof(buf));
      if (i <= 0) {
        goto read_parm_failed;
      }
      stat_req.path_length -= i;
    }
    if (write(sys, threadFd, &rc, sizeof(rc)) != sizeof(rc)) {
      die("Failed to return data from stat() [process]");
    }
    return false;
  }
  SecureMem::lockSystemCall(parentProc, mem);
  if (read(sys, sandboxFd, pathname, stat_req.path_length) !=
      stat_req.path_length) {
    goto read_parm_failed;
  }

  // TODO(markus): Implement sandboxing policy

  // Tell trusted thread to stat the file.
  SecureMem::sendSystemCall(threadFdPub, true, mem,
                            #if __WORDSIZE == 32
                            stat_req.sysnum == __NR_stat64 ? __NR_stat64 :
                            #endif
                            __NR_stat,
                            pathname - (char*)mem + (char*)mem->self,
                            stat_req.buf);
  return true;
}

} // namespace
