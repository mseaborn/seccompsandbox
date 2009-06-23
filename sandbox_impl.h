#ifndef SANDBOX_IMPL_H__
#define SANDBOX_IMPL_H__

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/prctl.h>
#include <linux/unistd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define NOINTR_SYS(x)                                                         \
 ({ int i__; while ((i__ = (x)) < 0 && Sandbox::sys_.my_errno == EINTR); i__;})

#ifdef __cplusplus
#include <iostream>
#include <map>
#include "sandbox.h"
#include "securemem.h"

namespace playground {

class Sandbox {
  // TODO(markus): restrict access to our private file handles
 public:
#define STATIC static
#else
#define STATIC
#endif
  STATIC int sandbox_clone(int flags, void* stack, int* pid, void* tls,
                           int* ctid, void* wrapper_sp);
  STATIC int sandbox_getpid();
  STATIC int sandbox_ioctl(int d, int req, void* arg);
  STATIC void *sandbox_mmap(void* start, size_t length, int prot, int flags,
                            int fd, off_t offset);
  STATIC int sandbox_mprotect(const void* addr, size_t len, int prot);
  STATIC int sandbox_munmap(void* start, size_t length);
  STATIC int sandbox_open(const char* pathname, int flags, mode_t mode);
  STATIC int sandbox_stat(const char* path, void* buf);
  #if __WORDSIZE == 32
  STATIC int sandbox_stat64(const char *path, void* buf);
  #endif

  STATIC void thread_clone(int fd);
  STATIC void thread_getpid(int fd);
  STATIC void thread_ioctl(int fd);
  STATIC void thread_mmap(int fd);
  STATIC void thread_mprotect(int fd);
  STATIC void thread_munmap(int fd);
  STATIC void thread_open(int fd);
  STATIC void thread_stat(int fd);

  STATIC void process_clone(int fd);
  STATIC void process_getpid(int fd);
  STATIC void process_ioctl(int fd);
  STATIC void process_mmap(int fd);
  STATIC void process_mprotect(int fd);
  STATIC void process_munmap(int fd);
  STATIC void process_open(int fd);
  STATIC void process_stat(int fd);

#ifdef __cplusplus
  class SysCalls {
   public:
    #define SYS_CPLUSPLUS
    #define SYS_ERRNO     my_errno
    #define SYS_INLINE    inline
    #define SYS_PREFIX    -1
    #undef  SYS_LINUX_SYSCALL_SUPPORT_H
    #include "linux_syscall_support.h"
    LSS_INLINE void* syscall(int num, void* arg0, void* arg1, void* arg2,
                             void* arg3, void* arg4, void* arg5) {
      long __res;
      #if __WORDSIZE == 64
      __asm__ __volatile__("movq %5,%%r10; movq %6,%%r8; movq %7,%%r9;"
                           "syscall" :
        "=a" (__res) : "0" (num),
        "D" ((long)(arg0)), "S" ((long)(arg1)), "d" ((long)(arg2)),
        "g" ((long)(arg3)), "g" ((long)(arg4)), "g" ((long)(arg5)) :
        "r8", "r9", "r10", "r11", "rcx", "memory");
      #else
      struct { int n; long a1; long a6; } s = { num, (long)arg0, (long) arg5 };
      __asm__ __volatile__("push %%ebp\n"
                           "push %%ebx\n"
                           "movl 8(%1), %%ebp\n"
                           "movl 4(%1), %%ebx\n"
                           "movl 0(%1), %%eax\n"
                           "int  $0x80\n"
                           "pop  %%ebx\n"
                           "pop  %%ebp"
                           : "=a" (__res)
                           : "0" ((long)(&s)),
                             "c" ((long)(arg1)), "d" ((long)(arg2)),
                             "S" ((long)(arg3)), "D" ((long)(arg4))
                           : "memory");
      #endif
      LSS_RETURN(void *,__res);
    }
    SysCalls() : my_errno(0) { }
    int my_errno;
  };

  struct Unrestricted {
    void* arg0;
    void* arg1;
    void* arg2;
    void* arg3;
    void* arg4;
    void* arg5;
  } __attribute__((packed));

  struct Clone {
    int   flags;
    void* stack;
    int*  pid;
    void* tls;
    int*  ctid;
    #if __WORDSIZE == 64
      struct {
        void* r11;
        void* r10;
        void* r9;
        void* r8;
        void* rdi;
        void* rsi;
        void* rdx;
        void* rcx;
        void* ret;
      } regs64 __attribute__((packed));
    #else
      struct {
        void* ebp;
        void* edi;
        void* esi;
        void* edx;
        void* ecx;
        void* ebx;
        void* ret1;
        void* ret2;
      } regs32 __attribute__((packed));
    #endif
  } __attribute__((packed));

  struct IOCtl {
    int  d;
    int  req;
    void *arg;
  } __attribute__((packed));

  struct MMap {
    void*  start;
    size_t length;
    int    prot;
    int    flags;
    int    fd;
    off_t  offset;
  } __attribute__((packed));

  struct MProtect {
    const void*  addr;
    size_t       len;
    int          prot;
  };

  struct MUnmap {
    void*  start;
    size_t length;
  } __attribute__((packed));

  struct Open {
    union {
      const char *path;
      int        path_length;
    };
    int    flags;
    mode_t mode;
  } __attribute__((packed));

  struct Stat {
    int          sysnum;
    union {
      const char *path;
      int        path_length;
    };
    void         *buf;
  } __attribute__((packed));

  typedef std::map<void *, long> ProtectedMap;

  static void startSandbox();
  static void die(const char *msg = 0) __attribute__((noreturn)) {
    if (msg) {
      sys_.write(2, msg, strlen(msg));
      sys_.write(2, "\n", 1);
    }
    _exit(1);
  }
  static int threadFd()         { return threadFd_; }
  static int processFd()        { return processFd_; }
  static SecureMem& secureMem() { return secureMem_; }
  static int my_errno()         { return sys_.my_errno; }

  static int read(int fd, void *buf, ssize_t len) {
    if (len < 0) {
      sys_.my_errno = EINVAL;
      return -1;
    }
    int offset = 0;
    while (offset < len) {
      int partial =
          NOINTR_SYS(sys_.read(fd, reinterpret_cast<char *>(buf) + offset,
                               len - offset));
      if (partial < 0) {
        return partial;
      } else if (!partial) {
        break;
      }
      offset += partial;
    }
    return offset;
  }

  static int write(int fd, const void *buf, size_t len) {
    return NOINTR_SYS(sys_.write(fd, buf, len));
  }

  static bool sendFd(int transport, int fd);
  static int getFd(int transport);

  static SysCalls     sys_;
  static SecureMem    secureMem_;

  static ProtectedMap protectedMap_; // available in trusted process, only

 private:
  struct ChildArgs {
   public:
    template<int n>static ChildArgs* pushArgs(char (&stack)[n], int fd) {
      ChildArgs *args =
          reinterpret_cast<ChildArgs *>(stack + n - sizeof(ChildArgs));
      args->fd = fd;
      return args;
    }
    int fd;
  };

  static void* defaultSystemCallHandler(int syscallNum, void *arg0, void *arg1,
                                        void *arg2, void *arg3, void *arg4,
                                        void *arg5);
  static void trustedThread(void *args) __attribute__((noreturn));
  static void trustedProcess(void *args) __attribute__((noreturn));
  static void createTrustedProcess(int fd, int closeFd);
  static void createTrustedThread(int fd);
  static void snapshotMemoryMappings();

  static char stack_[8192];
  static int  threadFd_;
  static int  processFd_;
  static int  pid_;
};

} // namespace

using playground::Sandbox;
#endif // __cplusplus

#endif // SANDBOX_IMPL_H__
