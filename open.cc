#include "sandbox_impl.h"

namespace playground {

int Sandbox::sandbox_open(const char *pathname, int flags, mode_t mode) {
  SysCalls sys;
  write(sys, 2, "open()\n", 7);
  struct {
    int   sysnum;
    pid_t tid;
    Open  open_req;
  } __attribute__((packed)) request;
  request.sysnum         = __NR_open;
  request.tid            = tid();
  request.open_req.path  = pathname;
  request.open_req.flags = flags;
  request.open_req.mode  = mode;

  int rc[sizeof(void *)/sizeof(int)];
  int thread = threadFd();
  if (write(sys, thread, &request, sizeof(request)) != sizeof(request) ||
      read(sys, thread, rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward open() request [sandbox]");
  }
  return rc[0];
}

void* Sandbox::thread_open(int processFd, pid_t tid, int threadFd, char* mem) {
  // Read request
  SysCalls sys;
  struct Request {
    int   sysnum;
    pid_t tid;
    Open  open_req;
  } __attribute__((packed)) request;
  request.sysnum = __NR_open;
  request.tid    = tid;
  if (read(sys, threadFd, &request.open_req, sizeof(request.open_req)) !=
      sizeof(request.open_req)) {
    die("Failed to read parameters for open() [thread]");
  }

  // Forward request to trusted process, and receive new file descriptor in
  // return
  // TODO(markus): Must coalesce writes to avoid race conditions.
  // TODO(markus): Maybe, move this code into sandbox_open()
  const char *pathname = request.open_req.path;
  request.open_req.path_length = strlen(pathname);
  if (write(sys, processFd, &request, sizeof(request)) != sizeof(request) ||
      write(sys, processFd, pathname, request.open_req.path_length) !=
      request.open_req.path_length) {
    die("Failed to forward open() request [thread]");
  }
  int rc;
  getFd(threadFd, &rc);
  return reinterpret_cast<void *>(rc);
}

void Sandbox::process_open(int sandboxFd, int threadFdPub, int threadFd,
                           char* mem) {
  // Read request
  SysCalls sys;
  Open open_req;
  if (read(sys, sandboxFd, &open_req, sizeof(open_req)) != sizeof(open_req)) {
 read_parm_failed:
    die("Failed to read parameters for open() [process]");
  }
  int rc = -ENAMETOOLONG;
  if (open_req.path_length > PATH_MAX) {
    char buf[32];
    while (open_req.path_length > 0) {
      int i = read(sys, sandboxFd, buf, sizeof(buf));
      if (i <= 0) {
        goto read_parm_failed;
      }
      open_req.path_length -= i;
    }
 reply_with_error:
    if (write(sys, threadFdPub, &rc, sizeof(rc)) != sizeof(rc)) {
      die("Failed to return data from open() [process]");
    }
    return;
  }
  char path[open_req.path_length + 1];
  if (read(sys, sandboxFd, path, open_req.path_length) !=open_req.path_length){
    goto read_parm_failed;
  }
  path[open_req.path_length] = '\000';

  // Open file
  // TODO(markus): Implement sandboxing policy
  // TODO(markus): Do we care that the trusted process sees slightly different
  // files than the sandbox'd process? Most notably /proc/self is different.
  // TODO(markus): A better solution is to send the system call, but to
  //               store the filename in the secure memory page
  int new_fd = sys.open(path, open_req.flags, open_req.mode);
  if (new_fd < 0) {
    rc = -sys.my_errno;
    goto reply_with_error;
  }

  // Send file handle back to trusted thread
  if (!sendFd(threadFdPub, new_fd)) {
    die("Failed to return file handle to sandbox [process]");
  }
  NOINTR_SYS(sys.close(new_fd));
}

} // namespace
