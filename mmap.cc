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

void Sandbox::thread_mmap(int processFd, pid_t tid, int threadFd, char* mem) {
  die("thread_mmap()");
}

void Sandbox::process_mmap(int sandboxFd, int processFd, int threadFd,
                           int cloneFd, char* mem) {
  // Read request
  SysCalls sys;
  MMap mmap_req;
  if (read(sys, processFd, &mmap_req, sizeof(mmap_req)) != sizeof(mmap_req)) {
    die("Failed to read parameters for mmap() [process]");
  }
  int rc = -EINVAL;
  if (mmap_req.flags & MAP_FIXED) {
    // TODO(markus): Allow MAP_FIXED if it doesn't clobber any reserved
    // mappings.
    // TODO(markus): Mark birthing place of secure memory as secure
    SecureMem::abandonSystemCall(threadFd, rc);
  } else {
    SecureMem::sendSystemCall(threadFd, mem, __NR_MMAP, mmap_req.start,
                               mmap_req.length, mmap_req.prot, mmap_req.flags,
                               mmap_req.fd, mmap_req.offset);
  }
}

} // namespace
