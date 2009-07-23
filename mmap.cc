#include "sandbox_impl.h"

namespace playground {

void* Sandbox::sandbox_mmap(void *start, size_t length, int prot, int flags,
                          int fd, off_t offset) {
  SysCalls sys;
  write(sys, 2, "mmap()\n", 7);
  struct {
    int       sysnum;
    long long cookie;
    MMap      mmap_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_MMAP;
  request.cookie          = cookie();
  request.mmap_req.start  = start;
  request.mmap_req.length = length;
  request.mmap_req.prot   = prot;
  request.mmap_req.flags  = flags;
  request.mmap_req.fd     = fd;
  request.mmap_req.offset = offset;

  void* rc;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward mmap() request [sandbox]");
  }
  return rc;
}

bool Sandbox::process_mmap(int parentProc, int sandboxFd, int threadFdPub,
                           int threadFd, SecureMem::Args* mem) {
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
    return false;
  } else {
    // TODO(markus): Even without MAP_FIXED, we have to ensure that we never
    // return addresses that are in our "protected" area at the bottom of
    // memory.
    SecureMem::sendSystemCall(threadFdPub, false, -1, mem, __NR_MMAP,
                              mmap_req.start, mmap_req.length, mmap_req.prot,
                              mmap_req.flags, mmap_req.fd, mmap_req.offset);
    return true;
  }
}

} // namespace
