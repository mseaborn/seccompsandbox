#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_munmap(void* start, size_t length) {
  SysCalls sys;
  write(sys, 2, "munmap()\n", 9);
  struct {
    int    sysnum;
    pid_t  tid;
    MUnmap munmap_req;
  } __attribute__((packed)) request;
  request.sysnum            = __NR_munmap;
  request.tid               = tid();
  request.munmap_req.start  = start;
  request.munmap_req.length = length;

  // Read the threadFd() before submitting the request, as we might be
  // unallocating our thread local storage.
  int thread = threadFd();
  long rc;
  if (write(sys, processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(sys, thread, &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward munmap() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::thread_munmap(int processFd, pid_t tid, int threadFd,
                            char* mem) {
  die("thread_munmap()");
}

void Sandbox::process_munmap(int processFdPub, int sandboxFd, int threadFd,
                             int cloneFdPub, char* mem) {
  // Read request
  SysCalls sys;
  MUnmap munmap_req;
  if (read(sys, sandboxFd, &munmap_req, sizeof(munmap_req)) !=
      sizeof(munmap_req)) {
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
      SecureMem::abandonSystemCall(threadFd, rc);
      return;
    }
  }

  // Unmapping memory regions that were newly mapped inside of the sandbox
  // is OK.
  SecureMem::sendSystemCall(threadFd, mem, __NR_munmap, munmap_req.start,
                            munmap_req.length);
}

} // namespace
