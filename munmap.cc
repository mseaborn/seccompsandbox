#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_munmap(void* start, size_t length) {
  write(2, "munmap()\n", 9);
  struct {
    int    sysnum;
    MUnmap munmap_req;
  } __attribute__((packed)) request;
  request.sysnum            = __NR_munmap;
  request.munmap_req.start  = start;
  request.munmap_req.length = length;

  long rc;
  if (write(processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward munmap() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::thread_munmap(int fd) {
  die("thread_munmap()");
}

void Sandbox::process_munmap(int fd) {
  // Read request
  MUnmap munmap_req;
  if (read(fd, &munmap_req, sizeof(munmap_req)) != sizeof(munmap_req)) {
    die("Failed to read parameters for munmap() [process]");
  }

  // Cannot unmap any memory region that was part of the original memory
  // mappings.
  int rc = -EINVAL;
  void *stop = reinterpret_cast<void *>(
      reinterpret_cast<char *>(munmap_req.start) + munmap_req.length);
  ProtectedMap::const_iterator iter = protectedMap_.lower_bound(
      munmap_req.start);
  if (iter != protectedMap_.begin()) {
    --iter;
  }
  for (; iter != protectedMap_.end() && iter->first < stop; ++iter) {
    if (munmap_req.start < reinterpret_cast<void *>(
            reinterpret_cast<char *>(iter->first) + iter->second) &&
        stop > iter->first) {
      secureMem().abandonSystemCall(threadFd(), rc);
      return;
    }
  }

  // Unmapping memory regions that were newly mapped inside of the sandbox
  // is OK.
  secureMem().sendSystemCall(threadFd(), __NR_munmap, munmap_req.start,
                             munmap_req.length);
}

} // namespace

extern "C" {
int sandbox_munmap(void *start, size_t length)
#if __WORDSIZE == 64
  __attribute__((alias("_ZN10playground7Sandbox14sandbox_munmapEPvm")));
#else
  __attribute__((alias("_ZN10playground7Sandbox14sandbox_munmapEPvj")));
#endif
void thread_munmap(int fd)
  __attribute__((alias("_ZN10playground7Sandbox13thread_munmapEi")));
void process_munmap(int fd)
  __attribute__((alias("_ZN10playground7Sandbox14process_munmapEi")));
} // extern "C"
