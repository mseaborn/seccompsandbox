#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_ioctl(int d, int req, void *arg) {
  write(2, "ioctl()\n", 8);
  struct {
    int   sysnum;
    IOCtl ioctl_req;
  } __attribute__((packed)) request;
  request.sysnum        = __NR_ioctl;
  request.ioctl_req.d   = d;
  request.ioctl_req.req = req;
  request.ioctl_req.arg = arg;

  long rc;
  if (write(processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward ioctl() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::thread_ioctl(int fd) {
  die("thread_ioctl()");
}

void Sandbox::process_ioctl(int fd) {
  // Read request
  IOCtl ioctl_req;
  if (read(fd, &ioctl_req, sizeof(ioctl_req)) != sizeof(ioctl_req)) {
    die("Failed to read parameters for ioctl() [process]");
  }
  int rc = -EINVAL;
  switch (ioctl_req.req) {
    case TCGETS:
    case TIOCGWINSZ:
      secureMem().sendSystemCall(threadFd(), __NR_ioctl, ioctl_req.d,
                                 ioctl_req.req, ioctl_req.arg);
      break;
    default:
      std::cout << "Unsupported ioctl: 0x" << std::hex << ioctl_req.req <<
          std::endl;
      secureMem().abandonSystemCall(threadFd(), rc);
      break;
  }
}

} // namespace

extern "C" {
int sandbox_ioctl(int d, int req, void *arg)
  __attribute__((alias("_ZN10playground7Sandbox13sandbox_ioctlEiiPv")));
void thread_ioctl(int fd)
  __attribute__((alias("_ZN10playground7Sandbox12thread_ioctlEi")));
void process_ioctl(int fd)
  __attribute__((alias("_ZN10playground7Sandbox13process_ioctlEi")));
} // extern "C"
