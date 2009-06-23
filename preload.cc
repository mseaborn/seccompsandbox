#include <unistd.h>

#include "sandbox_impl.h"

namespace playground {

extern "C" void preload() {
  startSandbox();
  write(2, "In secure mode, now!\n", 21);
  __asm__ __volatile__("int3");

// TODO(markus): This code is just a temporary hack. Remove when not needed.
#if __WORDSIZE == 64
  __asm__ __volatile__ (
      "sub $8, %rsp;"
      "push %rax;push %rbx;push %rcx;push %rdx;push %rbp;push %rsi;push %rdi;"
      "push %r8;push %r9;push %r10;push %r11;push %r12;push %r13;push %r14;"
      "push %r15;"
      "lea 120(%rsp), %rsi;mov $8, %rdx;mov $39, %rdi;mov $0, %rax;syscall;"
      "pop %r15;pop %r14;pop %r13;pop %r12;pop %r11;pop %r10;pop %r9;pop %r8;"
      "pop %rdi;pop %rsi;pop %rbp;pop %rdx;pop %rcx;pop %rbx;pop %rax;"
      "ret");
#endif
}

} // namespace
