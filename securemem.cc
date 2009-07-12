#include "sandbox_impl.h"
#include "securemem.h"

namespace playground {

void SecureMem::abandonSystemCall(int fd, int err) {
  int data[2] = { -1, err };
  if (err) write(2, "System call failed\n", 19); // TODO(markus): remove
  Sandbox::SysCalls sys;
  if (Sandbox::write(sys, fd, data, sizeof(data)) != sizeof(data)) {
    Sandbox::die("Failed to send system call");
  }
}

void SecureMem::sendSystemCallInternal(int fd, char *mem, int syscall_num,
                                       void *arg1, void *arg2, void *arg3,
                                       void *arg4, void *arg5, void *arg6) {
  // There is a special-case version of this code in clone.cc. If you make
  // any changes in the code here, make sure you make the same changes in
  // clone.cc
  #if __WORDSIZE == 64
  // TODO(markus): Check whether there is a security issue with us not being
  // able to change the shared memory page atomically. In particular, by
  // writing to threadFd(), malicious code could persuade the trusted thread
  // to run the same system call multiple times. Maybe, include a serial
  // number that has to increment sequentially?
  // TODO(markus): This code is currently not thread-safe.
  // B8 .. .. .. ..                   MOV  $..., %eax
  // 48 BF .. .. .. .. .. .. .. ..    MOV  $..., %rdi
  // 48 BE .. .. .. .. .. .. .. ..    MOV  $..., %rsi
  // 48 BA .. .. .. .. .. .. .. ..    MOV  $..., %rdx
  // 49 BA .. .. .. .. .. .. .. ..    MOV  $..., %r10
  // 49 B8 .. .. .. .. .. .. .. ..    MOV  $..., %r8
  // 49 B9 .. .. .. .. .. .. .. ..    MOV  $..., %r9
  // 0F 05                            SYSCALL
  // 48 B9 .. .. .. .. .. .. .. ..    MOV  $0x..., %rcx
  // FF E1                            JMP  *%rcx
  memcpy(mem,
         "\xB8\x00\x00\x00\x00"
         "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x0F\x05"
         "\x48\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
         "\xFF\xE1", 79);

  *reinterpret_cast<int   *>(mem +  1) = syscall_num;
  *reinterpret_cast<void **>(mem +  7) = arg1;
  *reinterpret_cast<void **>(mem + 17) = arg2;
  *reinterpret_cast<void **>(mem + 27) = arg3;
  *reinterpret_cast<void **>(mem + 37) = arg4;
  *reinterpret_cast<void **>(mem + 47) = arg5;
  *reinterpret_cast<void **>(mem + 57) = arg6;
  *reinterpret_cast<void **>(mem + 69) =
      (void*)Sandbox::getTrustedThreadReturnResult();
  #else
  // TODO(markus): it is not safe to store %ebp and %ebx on the stack
  // 55                               PUSH %ebp
  // 53                               PUSH %ebx
  // B8 .. .. .. ..                   MOV  $..., %eax
  // BB .. .. .. ..                   MOV  $..., %ebx
  // B9 .. .. .. ..                   MOV  $..., %ecx
  // BA .. .. .. ..                   MOV  $..., %edx
  // BE .. .. .. ..                   MOV  $..., %esi
  // BF .. .. .. ..                   MOV  $..., %edi
  // BD .. .. .. ..                   MOV  $..., %ebp
  // CD 80                            INT  $0x80
  // 5B                               POP  %ebx
  // 5D                               POP  %ebp
  // C3                               RET
  memcpy(mem,
         "\x55"
         "\x53"
         "\xB8\x00\x00\x00\x00"
         "\xBB\x00\x00\x00\x00"
         "\xB9\x00\x00\x00\x00"
         "\xBA\x00\x00\x00\x00"
         "\xBE\x00\x00\x00\x00"
         "\xBF\x00\x00\x00\x00"
         "\xBD\x00\x00\x00\x00"
         "\xCD\x80"
         "\x5B"
         "\x5D"
         "\xC3", 42);
  *reinterpret_cast<int   *>(mem +  3) = syscall_num;
  *reinterpret_cast<void **>(mem +  8) = arg1;
  *reinterpret_cast<void **>(mem + 13) = arg2;
  *reinterpret_cast<void **>(mem + 18) = arg3;
  *reinterpret_cast<void **>(mem + 23) = arg4;
  *reinterpret_cast<void **>(mem + 28) = arg5;
  *reinterpret_cast<void **>(mem + 33) = arg6;
  #endif
  abandonSystemCall(fd, 0);
}

} // namespace
