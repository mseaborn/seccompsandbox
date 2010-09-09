// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mutex.h"
#include "sandbox_impl.h"

// This is a C++ implementation of trusted_thread.cc.  Since it trusts
// the contents of the stack, it is not secure.  It is intended to be
// a reference implementation.  This code can be used as an aid to
// understanding what the real trusted thread does, since this code
// should be easier to read than assembly code.  It can also be used
// as a test bed for changes to the trusted thread.

namespace playground {

void die(const char *msg) {
  sys_write(2, msg, strlen(msg));
  sys_exit_group(1);
}

#define TO_STRING_1(x) #x
#define TO_STRING(x) TO_STRING_1(x)

#define assert(expr) { \
  if (!(expr)) die("assertion failed at " __FILE__ ":" TO_STRING(__LINE__) \
                   ": " #expr "\n"); }

// Perform a syscall given an array of syscall arguments.
extern "C" long DoSyscall(long regs[7]);
asm(
    ".pushsection .text, \"ax\", @progbits\n"
    ".global DoSyscall\n"
    "DoSyscall:\n"
#if defined(__x86_64__)
    "push %rdi\n"
    "push %rsi\n"
    "push %rdx\n"
    "push %r10\n"
    "push %r8\n"
    "push %r9\n"
    // Set up syscall arguments
    "mov 0x00(%rdi), %rax\n"
    // Skip 0x08 (%rdi): this comes last
    "mov 0x10(%rdi), %rsi\n"
    "mov 0x18(%rdi), %rdx\n"
    "mov 0x20(%rdi), %r10\n"
    "mov 0x28(%rdi), %r8\n"
    "mov 0x30(%rdi), %r9\n"
    "mov 0x08(%rdi), %rdi\n"
    "syscall\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %r10\n"
    "pop %rdx\n"
    "pop %rsi\n"
    "pop %rdi\n"
    "ret\n"
#elif defined(__i386__)
    "push %ebx\n"
    "push %ecx\n"
    "push %edx\n"
    "push %esi\n"
    "push %edi\n"
    "push %ebp\n"
    "mov 4+24(%esp), %ecx\n"
    // Set up syscall arguments
    "mov 0x00(%ecx), %eax\n"
    "mov 0x04(%ecx), %ebx\n"
    // Skip 0x08 (%ecx): this comes last
    "mov 0x0c(%ecx), %edx\n"
    "mov 0x10(%ecx), %esi\n"
    "mov 0x14(%ecx), %edi\n"
    "mov 0x18(%ecx), %ebp\n"
    "mov 0x08(%ecx), %ecx\n"
    "int $0x80\n"
    "pop %ebp\n"
    "pop %edi\n"
    "pop %esi\n"
    "pop %edx\n"
    "pop %ecx\n"
    "pop %ebx\n"
    "ret\n"
#else
#error Unsupported target platform
#endif
    ".popsection\n"
    );

void ReturnFromCloneSyscall(SecureMem::Args *secureMem) {
  // TODO(mseaborn): Call sigreturn() to unblock signals.
#if defined(__x86_64__)
  // Get stack argument that was passed to clone().
  void **stack = (void**) secureMem->rsi;
  // Account for the x86-64 red zone adjustment that our syscall
  // interceptor does when returning from the system call.
  stack = (void**) ((char*) stack - 128);
  *--stack = secureMem->ret;
  *--stack = secureMem->r15;
  *--stack = secureMem->r14;
  *--stack = secureMem->r13;
  *--stack = secureMem->r12;
  *--stack = secureMem->r11;
  *--stack = secureMem->r10;
  *--stack = secureMem->r9;
  *--stack = secureMem->r8;
  *--stack = secureMem->rdi;
  *--stack = secureMem->rsi;
  *--stack = secureMem->rdx;
  *--stack = secureMem->rcx;
  *--stack = secureMem->rbx;
  *--stack = secureMem->rbp;
  asm("mov %0, %%rsp\n"
      "pop %%rbp\n"
      "pop %%rbx\n"
      "pop %%rcx\n"
      "pop %%rdx\n"
      "pop %%rsi\n"
      "pop %%rdi\n"
      "pop %%r8\n"
      "pop %%r9\n"
      "pop %%r10\n"
      "pop %%r11\n"
      "pop %%r12\n"
      "pop %%r13\n"
      "pop %%r14\n"
      "pop %%r15\n"
      "mov $0, %%rax\n"
      "ret\n"
      : : "m"(stack));
#elif defined(__i386__)
  // Get stack argument that was passed to clone().
  void **stack = (void**) secureMem->ecx;
  *--stack = secureMem->ret;
  *--stack = secureMem->ebp;
  *--stack = secureMem->edi;
  *--stack = secureMem->esi;
  *--stack = secureMem->edx;
  *--stack = secureMem->ecx;
  *--stack = secureMem->ebx;
  asm("mov %0, %%esp\n"
      "pop %%ebx\n"
      "pop %%ecx\n"
      "pop %%edx\n"
      "pop %%esi\n"
      "pop %%edi\n"
      "pop %%ebp\n"
      "mov $0, %%eax\n"
      "ret\n"
      : : "m"(stack));
#else
#error Unsupported target platform
#endif
}

void InitCustomTLS(void *addr) {
  Sandbox::SysCalls sys;
#if defined(__x86_64__)
  int rc = sys.arch_prctl(ARCH_SET_GS, addr);
  assert(rc == 0);
#elif defined(__i386__)
  struct user_desc u;
  u.entry_number    = (typeof u.entry_number)-1;
  u.base_addr       = (long) addr;
  u.limit           = 0xfffff;
  u.seg_32bit       = 1;
  u.contents        = 0;
  u.read_exec_only  = 0;
  u.limit_in_pages  = 1;
  u.seg_not_present = 0;
  u.useable         = 1;
  int rc = sys.set_thread_area(&u);
  assert(rc == 0);
  asm volatile("movw %w0, %%fs"
               : : "q"(8 * u.entry_number + 3));
#else
#error Unsupported target platform
#endif
}

void UnlockSyscallMutex() {
  Sandbox::SysCalls sys;
  // TODO(mseaborn): Use clone() to be the same as trusted_thread.cc.
  int pid = sys.fork();
  assert(pid >= 0);
  if (pid == 0) {
    int rc = sys.mprotect(&Sandbox::syscall_mutex_, 0x1000,
                          PROT_READ | PROT_WRITE);
    assert(rc == 0);
    Mutex::unlockMutex(&Sandbox::syscall_mutex_);
    sys._exit(0);
  }
  int status;
  int rc = sys.waitpid(pid, &status, 0);
  assert(rc == pid);
  assert(status == 0);
}

// Allocate a stack that is never freed.
char *AllocateStack() {
  Sandbox::SysCalls sys;
  int stack_size = 0x1000;
#if defined(__i386__)
  void *stack = sys.mmap2(NULL, stack_size, PROT_READ | PROT_WRITE,
                          MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#else
  void *stack = sys.mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
#endif
  assert(stack != MAP_FAILED);
  return (char *) stack + stack_size;
}

int HandleNewThread(void *arg) {
  SecureMem::Args *secureMem = (SecureMem::Args *) arg;
  CreateReferenceTrustedThread(secureMem->newSecureMem);
  ReturnFromCloneSyscall(secureMem);
  return 0;
}

struct ThreadArgs {
  SecureMem::Args *secureMem;
  int threadFd;
};

int TrustedThread(void *arg) {
  struct ThreadArgs *args = (struct ThreadArgs *) arg;
  SecureMem::Args *secureMem = args->secureMem;
  int fd = args->threadFd;
  Sandbox::SysCalls sys;

  int sequence_no = 2;
  while (1) {
    long syscall_args[7];
    memset(syscall_args, 0, sizeof(syscall_args));
    int got = sys.read(fd, syscall_args, 4);
    assert(got == 4);

    long syscall_result;
    int sysnum = syscall_args[0];
    if (sysnum == -1 || sysnum == -2) {
      // Syscall where the registers have been checked by the trusted
      // process, e.g. munmap() ranges must be OK.
      // We check the sequence number before and after reading the
      // syscall register data, in case this data is changed as we
      // read it.
      assert(secureMem->sequence == sequence_no);
      memcpy(syscall_args, &secureMem->syscallNum, sizeof(syscall_args));
      assert(secureMem->sequence == sequence_no);
      sequence_no += 2;
      if (syscall_args[0] == __NR_exit) {
        assert(sysnum == -2);
        int rc = sys.close(fd);
        assert(rc == 0);
        rc = sys.close(secureMem->threadFdPub);
        assert(rc == 0);
        // Make the thread's memory area inaccessible as a sanity check.
        rc = sys.mprotect(secureMem, 0x2000, PROT_NONE);
        assert(rc == 0);
        // Although the thread exit syscall does not read from the
        // secure memory area, we use the mutex for it to ensure that
        // the trusted process and trusted thread are synchronised.
        // We do not want the trusted process to think that the
        // thread's memory area has been freed while the trusted
        // thread is still reading from it.
        UnlockSyscallMutex();
        sys._exit(1);
      }
      else if (syscall_args[0] == __NR_clone) {
        assert(sysnum == -2);
        // Note that HandleNewThread() does UnlockSyscallMutex() for us.
#if defined(__x86_64__)
        long clone_flags = (long) secureMem->rdi;
        int *pid_ptr = (int *) secureMem->rdx;
        int *tid_ptr = (int *) secureMem->r10;
        void *tls_info = secureMem->r8;
#elif defined(__i386__)
        long clone_flags = (long) secureMem->ebx;
        int *pid_ptr = (int *) secureMem->edx;
        void *tls_info = secureMem->esi;
        int *tid_ptr = (int *) secureMem->edi;
#else
#error Unsupported target platform
#endif
        syscall_result = sys.clone(HandleNewThread, (void *) AllocateStack(),
                                   clone_flags, (void *) secureMem,
                                   pid_ptr, tls_info, tid_ptr);
        assert(syscall_result > 0);
        int sent = sys.write(fd, &syscall_result, sizeof(syscall_result));
        assert(sent == sizeof(syscall_result));
        continue;
      }
    }
    else if (sysnum == -3) {
      // RDTSC request.  Send back a dummy answer.
      int timestamp[2] = {0, 0};
      int sent = sys.write(fd, (char *) timestamp, sizeof(timestamp));
      assert(sent == 8);
      continue;
    }
    else {
      int rest_size = sizeof(syscall_args) - sizeof(long);
      got = sys.read(fd, &syscall_args[1], rest_size);
      assert(got == rest_size);
    }
    syscall_result = DoSyscall(syscall_args);
    if (sysnum == -2) {
      // This syscall involves reading from the secure memory area for
      // the thread.  We should only unlock this area when the syscall
      // has completed.  Otherwise, the trusted process might
      // overwrite the data while the kernel is still reading it.
      UnlockSyscallMutex();
    }
    int sent = sys.write(fd, &syscall_result, sizeof(syscall_result));
    assert(sent == sizeof(syscall_result));
  }
  return 0;
}

void CreateReferenceTrustedThread(SecureMem::Args *secureMem) {
  // We are in the nascent thread.
  Sandbox::SysCalls sys;

  int socks[2];
  int rc = sys.socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
  assert(rc == 0);
  int threadFdPub = socks[0];
  int threadFd = socks[1];

  // Create trusted thread.
  // We omit CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID.
  int flags = CLONE_VM | CLONE_FS | CLONE_FILES |
    CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
  // Assumes that the stack grows down.
  char *stack_top = AllocateStack() - sizeof(struct ThreadArgs);
  struct ThreadArgs *thread_args = (struct ThreadArgs *) stack_top;
  thread_args->threadFd = threadFd;
  thread_args->secureMem = secureMem;
  rc = sys.clone(TrustedThread, stack_top, flags, thread_args,
                 NULL, NULL, NULL);
  assert(rc > 0);

  // Make the thread state pages usable.
  rc = sys.mprotect(secureMem, 0x1000, PROT_READ);
  assert(rc == 0);
  rc = sys.mprotect(((char *) secureMem) + 0x1000, 0x1000,
                    PROT_READ | PROT_WRITE);
  assert(rc == 0);

  // Using cookie as the start is a little odd because other code in
  // syscall.c works around this when addressing from %fs.
  void *tls = (void*) &secureMem->cookie;
  InitCustomTLS(tls);

  UnlockSyscallMutex();

  int tid = sys.gettid();
  assert(tid > 0);

  // Send the socket FDs to the trusted process.
  // TODO(mseaborn): Don't duplicate this struct in trusted_process.cc
  struct {
    SecureMem::Args* self;
    int              tid;
    int              fdPub;
  } __attribute__((packed)) data;
  data.self = secureMem;
  data.tid = tid;
  data.fdPub = threadFdPub;
  bool ok = Sandbox::sendFd(Sandbox::cloneFdPub_, threadFdPub, threadFd,
                            (void *) &data, sizeof(data));
  assert(ok);

  // Wait for the trusted process to fill out the thread state for us.
  char byte_message;
  int got = sys.read(threadFdPub, &byte_message, 1);
  assert(got == 1);
  assert(byte_message == 0);

  // Switch to seccomp mode.
  rc = sys.prctl(PR_SET_SECCOMP, 1);
  assert(rc == 0);
}

}
