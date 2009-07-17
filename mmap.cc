#include "sandbox_impl.h"

namespace playground {

#if __WORDSIZE == 64
#define __NR_MMAP __NR_mmap
#else
#define __NR_MMAP __NR_mmap2
#endif

void* Sandbox::sandbox_mmap(void *start, size_t length, int prot, int flags,
                          int fd, off_t offset) {
  SysCalls sys;
  write(sys, 2, "mmap()\n", 7);
  struct {
    int   sysnum;
    pid_t tid;
    MMap  mmap_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_MMAP;
  request.tid             = tid();
  request.mmap_req.start  = start;
  request.mmap_req.length = length;
  request.mmap_req.prot   = prot;
  request.mmap_req.flags  = flags;
  request.mmap_req.fd     = fd;
  request.mmap_req.offset = offset;

  void* rc;
  if (write(sys, processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(sys, threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward mmap() request [sandbox]");
  }
  return rc;
}

void Sandbox::process_mmap(int sandboxFd, int threadFdPub, int threadFd,
                           SecureMem::Args* mem) {
  // Read request
  SysCalls sys;
  MMap mmap_req;
  if (read(sys, sandboxFd, &mmap_req, sizeof(mmap_req)) != sizeof(mmap_req)) {
    die("Failed to read parameters for mmap() [process]");
  }
  int rc = -EINVAL;
  if (mmap_req.flags & MAP_FIXED) {
    // TODO(markus): Allow MAP_FIXED if it doesn't clobber any reserved
    // mappings.
    SecureMem::abandonSystemCall(threadFd, rc);
  } else {
    mem->secureCradle = secureCradle();
    SecureMem::sendSystemCall(threadFdPub, false, mem, __NR_MMAP,
                              mmap_req.start, mmap_req.length, mmap_req.prot,
                              mmap_req.flags, mmap_req.fd, mmap_req.offset);
  }
}

} // namespace
