#include "sandbox_impl.h"

namespace playground {

int Sandbox::sandbox_open(const char *pathname, int flags, mode_t mode) {
  write(2, "open()\n", 7);
  struct {
    int sysnum;
    Open open_req;
  } __attribute__((packed)) request;
  request.sysnum         = __NR_open;
  request.open_req.path  = pathname;
  request.open_req.flags = flags;
  request.open_req.mode  = mode;

  int rc, thread = threadFd();
  if (write(thread, &request, sizeof(request)) != sizeof(request) ||
      read(thread, &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward open() request [sandbox]");
  }
  return rc;
}

void Sandbox::thread_open(int fd) {
  // Read request
  struct Request {
    int sysnum;
    Open open_req;
  } __attribute__((packed)) request;
  request.sysnum = __NR_open;
  if (read(fd, &request.open_req, sizeof(request.open_req)) !=
                 sizeof(request.open_req)) {
    die("Failed to read parameters for open() [thread]");
  }

  // Forward request to trusted process, and receive new file descriptor in
  // return
  const char *pathname = request.open_req.path;
  request.open_req.path_length = strlen(pathname);
  int process = processFd();
  if (write(process, &request, sizeof(request)) != sizeof(request) ||
      write(process, pathname, request.open_req.path_length) !=
      request.open_req.path_length) {
 forward_failed:
    die("Failed to forward open() request [thread]");
  }
  int rc = Sandbox::getFd(process);
  if (write(fd, &rc, sizeof(rc)) != sizeof(rc)) {
    goto forward_failed;
  }
}

void Sandbox::process_open(int fd) {
  // Read request
  Open open_req;
  if (read(fd, &open_req, sizeof(open_req)) != sizeof(open_req)) {
 read_parm_failed:
    die("Failed to read parameters for open() [process]");
  }
  int rc = -ENAMETOOLONG;
  if (open_req.path_length > PATH_MAX) {
    char buf[32];
    while (open_req.path_length > 0) {
      int i = read(fd, buf, sizeof(buf));
      if (i <= 0) {
        goto read_parm_failed;
      }
      open_req.path_length -= i;
    }
 reply_with_error:
    if (write(fd, &rc, sizeof(rc)) != sizeof(rc)) {
      die("Failed to return data from open() [process]");
    }
    return;
  }
  char path[open_req.path_length + 1];
  if (read(fd, path, open_req.path_length) != open_req.path_length) {
    goto read_parm_failed;
  }
  path[open_req.path_length] = '\000';

  // Open file
  // TODO(markus): Implement sandboxing policy
  // TODO(markus): Do we care that the trusted process sees slightly different
  // files than the sandbox'd process? Most notably /proc/self is different.
  int new_fd = sys_.open(path, open_req.flags, open_req.mode);
  if (new_fd < 0) {
    rc = -my_errno();
    goto reply_with_error;
  }

  // Send file handle back to trusted thread
  if (!Sandbox::sendFd(fd, new_fd)) {
    die("Failed to return file handle to sandbox [process]");
  }
  NOINTR_SYS(sys_.close(new_fd));
}

} // namespace

extern "C" {
int sandbox_open(int fd, void *buf)
   __attribute__((alias("_ZN10playground7Sandbox12sandbox_openEPKcij")));
void thread_open(int fd)
    __attribute__((alias("_ZN10playground7Sandbox11thread_openEi")));
void process_open(int fd)
    __attribute__((alias("_ZN10playground7Sandbox12process_openEi")));
} // extern "C"
