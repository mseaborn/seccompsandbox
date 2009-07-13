#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_mprotect(const void *addr, size_t len, int prot) {
  SysCalls sys;
  write(sys, 2, "mprotect()\n", 11);
  struct {
    int      sysnum;
    pid_t    tid;
    MProtect mprotect_req;
  } __attribute__((packed)) request;
  request.sysnum            = __NR_mprotect;
  request.tid               = tid();
  request.mprotect_req.addr = addr;
  request.mprotect_req.len  = len;
  request.mprotect_req.prot = prot;

  long rc;
  if (write(sys, processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(sys, threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward mprotect() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::thread_mprotect(int processFd, pid_t tid, int threadFd,
                              char* mem) {
  die("thread_mprotect()");
}

void Sandbox::process_mprotect(int processFdPub, int sandboxFd, int threadFd,
                               int cloneFdPub, char* mem) {
  // Read request
  SysCalls sys;
  MProtect mprotect_req;
  if (read(sys, sandboxFd, &mprotect_req, sizeof(mprotect_req)) !=
      sizeof(mprotect_req)) {
    die("Failed to read parameters for mprotect() [process]");
  }

  // Cannot change permissions on any memory region that was part of the
  // original memory mappings.
  int rc = -EINVAL;
  void *stop = reinterpret_cast<void *>(
      (char *)mprotect_req.addr + mprotect_req.len);
  ProtectedMap::const_iterator iter = protectedMap_.lower_bound(
      (void *)mprotect_req.addr);
  if (iter != protectedMap_.begin()) {
    --iter;
  }
  for (; iter != protectedMap_.end() && iter->first < stop; ++iter) {
    if (mprotect_req.addr < reinterpret_cast<void *>(
            reinterpret_cast<char *>(iter->first) + iter->second) &&
        stop > iter->first) {
      SecureMem::abandonSystemCall(threadFd, rc);
      return;
    }
  }

  // Changing permissions on memory regions that were newly mapped inside of
  // the sandbox is OK.
  SecureMem::sendSystemCall(threadFd, mem, __NR_mprotect, mprotect_req.addr,
                             mprotect_req.len, mprotect_req.prot);
}

} // namespace
