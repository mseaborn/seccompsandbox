#include "sandbox_impl.h"
#include "securemem.h"

namespace playground {

void SecureMem::abandonSystemCall(int fd, int err) {
  void* rc = reinterpret_cast<void *>(err);
  if (err) write(2, "System call failed\n", 19); // TODO(markus): remove
  Sandbox::SysCalls sys;
  if (Sandbox::write(sys, fd, rc, sizeof(rc)) != sizeof(rc)) {
    Sandbox::die("Failed to send system call");
  }
}

void SecureMem::submitSystemCall(int fd, bool locked) {
  int data[] = { locked ? -2 : -1, 0 };
  Sandbox::SysCalls sys;
  if (Sandbox::write(sys, fd, data, sizeof(data)) != sizeof(data)) {
    Sandbox::die("Failed to send system call");
  }
}

void SecureMem::sendSystemCallInternal(int fd, bool locked, char *mem,
                                       int syscall_num, void *arg1, void *arg2,
                                       void *arg3, void *arg4, void *arg5,
                                       void *arg6) {
  void **args = reinterpret_cast<void **>(mem);
  asm volatile(
    #if defined(__x86_64__)
      "lock; incq (%0)\n"
    #elif defined(__i386__)
      "lock; incl (%0)\n"
    #else
      #error Unsupported target platform
    #endif
      :
      : "q"(mem)
      : "memory");
  args[1] = reinterpret_cast<void *>(syscall_num);
  args[2] = reinterpret_cast<void *>(arg1);
  args[3] = reinterpret_cast<void *>(arg2);
  args[4] = reinterpret_cast<void *>(arg3);
  args[5] = reinterpret_cast<void *>(arg4);
  args[6] = reinterpret_cast<void *>(arg5);
  args[7] = reinterpret_cast<void *>(arg6);
  asm volatile(
    #if defined(__x86_64__)
      "lock; incq (%0)\n"
    #elif defined(__i386__)
      "lock; incl (%0)\n"
    #else
      #error Unsupported target platform
    #endif
      :
      : "q"(mem)
      : "memory");
  submitSystemCall(fd, locked);
}

} // namespace
