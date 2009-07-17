#include "sandbox_impl.h"

namespace playground {
int Sandbox::sandbox_ioctl(int d, int req, void *arg) {
  SysCalls sys;
  write(sys, 2, "ioctl()\n", 8);
  struct {
    int   sysnum;
    pid_t tid;
    IOCtl ioctl_req;
  } __attribute__((packed)) request;
  request.sysnum        = __NR_ioctl;
  request.tid           = tid();
  request.ioctl_req.d   = d;
  request.ioctl_req.req = req;
  request.ioctl_req.arg = arg;

  long rc;
  if (write(sys, processFd(), &request, sizeof(request)) != sizeof(request) ||
      read(sys, threadFd(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward ioctl() request [sandbox]");
  }
  return static_cast<int>(rc);
}

void Sandbox::process_ioctl(int sandboxFd, int threadFdPub, int threadFd,
                            SecureMem::Args* mem) {
  // Read request
  IOCtl ioctl_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &ioctl_req, sizeof(ioctl_req)) !=sizeof(ioctl_req)){
    die("Failed to read parameters for ioctl() [process]");
  }
  int rc = -EINVAL;
  switch (ioctl_req.req) {
    case TCGETS:
    case TIOCGWINSZ:
      SecureMem::sendSystemCall(threadFdPub, false, mem, __NR_ioctl,
                                ioctl_req.d, ioctl_req.req, ioctl_req.arg);
      break;
    default:
      std::cout << "Unsupported ioctl: 0x" << std::hex << ioctl_req.req <<
          std::endl;
      SecureMem::abandonSystemCall(threadFd, rc);
      break;
  }
}

} // namespace
