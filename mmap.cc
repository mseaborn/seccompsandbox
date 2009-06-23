#include "sandbox_impl.h"

namespace playground {

#if __WORDSIZE == 64
#define __NR_MMAP __NR_mmap
#else
#define __NR_MMAP __NR_mmap2
#endif

void* Sandbox::sandbox_mmap(void *start, size_t length, int prot, int flags,
                          int fd, off_t offset) {
  write(2, "mmap()\n", 7);
  struct {
    int  sysnum;
    MMap mmap_req;
  } __attribute__((packed)) request;
  request.sysnum          = __NR_MMAP;
  request.mmap_req.start  = start;
  request.mmap_req.length = length;
  request.mmap_req.prot   = prot;
  request.mmap_req.flags  = flags;
  request.mmap_req.fd     = fd;
  request.mmap_req.offset = offset;

  void* rc;
  if (write(processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward mmap() request [sandbox]");
  }
  return rc;
}

void Sandbox::thread_mmap(int fd) {
  die("thread_mmap()");
}

void Sandbox::process_mmap(int fd) {
  // Read request
  MMap mmap_req;
  if (read(fd, &mmap_req, sizeof(mmap_req)) != sizeof(mmap_req)) {
    die("Failed to read parameters for mmap() [process]");
  }
  int rc = -EINVAL;
  if (mmap_req.flags & MAP_FIXED) {
    secureMem().abandonSystemCall(threadFd(), rc);
  } else {
    secureMem().sendSystemCall(threadFd(), __NR_MMAP, mmap_req.start,
                               mmap_req.length, mmap_req.prot, mmap_req.flags,
                               mmap_req.fd, mmap_req.offset);
  }
}

} // namespace

extern "C" {
void *sandbox_mmap(void *start, size_t length, int prot, int flags,
                   int fd, off_t offset)
#if __WORDSIZE == 64
  __attribute__((alias("_ZN10playground7Sandbox12sandbox_mmapEPvmiiil")));
#else
  __attribute__((alias("_ZN10playground7Sandbox12sandbox_mmapEPvjiiil")));
#endif
void thread_mmap(int fd)
  __attribute__((alias("_ZN10playground7Sandbox11thread_mmapEi")));
void process_mmap(int fd)
  __attribute__((alias("_ZN10playground7Sandbox12process_mmapEi")));
} // extern "C"
