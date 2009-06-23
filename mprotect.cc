#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_mprotect(const void *addr, size_t len, int prot) {
  write(2, "mprotect()\n", 11);
  struct {
    int      sysnum;
    MProtect mprotect_req;
  } __attribute__((packed)) request;
  request.sysnum            = __NR_mprotect;
  request.mprotect_req.addr = addr;
  request.mprotect_req.len  = len;
  request.mprotect_req.prot = prot;

  long rc;
  if (write(processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward mprotect() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::thread_mprotect(int fd) {
  die("thread_mprotect()");
}

void Sandbox::process_mprotect(int fd) {
  // Read request
  MProtect mprotect_req;
  if (read(fd, &mprotect_req, sizeof(mprotect_req)) != sizeof(mprotect_req)) {
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
      secureMem().abandonSystemCall(threadFd(), rc);
      return;
    }
  }

  // Changing permissions on memory regions that were newly mapped inside of
  // the sandbox is OK.
  secureMem().sendSystemCall(threadFd(), __NR_mprotect, mprotect_req.addr,
                             mprotect_req.len, mprotect_req.prot);
}

} // namespace

extern "C" {
int sandbox_mprotect(const void *addr, size_t len, int prot)
#if __WORDSIZE == 64
   __attribute__((alias("_ZN10playground7Sandbox16sandbox_mprotectEPKvmi")));
#else
   __attribute__((alias("_ZN10playground7Sandbox16sandbox_mprotectEPKvji")));
#endif
void thread_mprotect(int fd)
    __attribute__((alias("_ZN10playground7Sandbox15thread_mprotectEi")));
void process_mprotect(int fd)
    __attribute__((alias("_ZN10playground7Sandbox16process_mprotectEi")));
} // extern "C"
