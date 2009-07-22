#include "sandbox_impl.h"

namespace playground {

int Sandbox::sandbox_open(const char *pathname, int flags, mode_t mode) {
  SysCalls sys;
  write(sys, 2, "open()\n", 7);
  int len                = strlen(pathname);
  struct Request {
    int       sysnum;
    long long cookie;
    Open      open_req;
    char      pathname[0];
  } __attribute__((packed)) *request;
  char data[sizeof(struct Request) + len];
  request                       = reinterpret_cast<struct Request*>(data);
  request->sysnum               = __NR_open;
  request->cookie               = cookie();
  request->open_req.path_length = len;
  request->open_req.flags       = flags;
  request->open_req.mode        = mode;
  memcpy(request->pathname, pathname, len);

  long rc;
  if (write(sys, processFdPub(), request, sizeof(data)) != (int)sizeof(data) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward open() request [sandbox]");
  }
  return static_cast<int>(rc);
}

bool Sandbox::process_open(int parentProc, int sandboxFd, int threadFdPub,
                           int threadFd, SecureMem::Args* mem) {
  // Read request
  SysCalls sys;
  Open open_req;
  if (read(sys, sandboxFd, &open_req, sizeof(open_req)) != sizeof(open_req)) {
 read_parm_failed:
    die("Failed to read parameters for open() [process]");
  }
  int   rc                  = -ENAMETOOLONG;
  char* pathname            = getSecureStringBuffer(open_req.path_length);
  if (!pathname) {
    char buf[32];
    while (open_req.path_length > 0) {
      int i = read(sys, sandboxFd, buf, sizeof(buf));
      if (i <= 0) {
        goto read_parm_failed;
      }
      open_req.path_length -= i;
    }
    if (write(sys, threadFd, &rc, sizeof(rc)) != sizeof(rc)) {
      die("Failed to return data from open() [process]");
    }
    return false;
  }
  SecureMem::lockSystemCall(parentProc, mem);
  if (read(sys, sandboxFd, pathname, open_req.path_length) !=
      open_req.path_length) {
    goto read_parm_failed;
  }

  // TODO(markus): Implement sandboxing policy

  // Tell trusted thread to open the file.
  SecureMem::sendSystemCall(threadFdPub, true, mem, __NR_open,
                            pathname - (char*)mem + (char*)mem->self,
                            open_req.flags, open_req.mode);
  return true;
}

} // namespace
