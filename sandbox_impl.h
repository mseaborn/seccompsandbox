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
 ({ int i__; while ((i__ = (x)) < 0 && sys.my_errno == EINTR); i__;})

#ifdef __cplusplus
#include <iostream>
#include <map>
#include "sandbox.h"
#include "securemem.h"
#include "tls.h"

namespace playground {

class Sandbox {
  // TODO(markus): restrict access to our private file handles
 public:
  enum { TLS_TID, TLS_THREAD_FD, TLS_PROCESS_FD, TLS_CLONE_FD };

  static int tid()       { return TLS::getTLSValue<int>(TLS_TID); }
  static int threadFd()  { return TLS::getTLSValue<int>(TLS_THREAD_FD); }
  static int processFd() { return TLS::getTLSValue<int>(TLS_PROCESS_FD); }
  static int cloneFd()   { return TLS::getTLSValue<int>(TLS_CLONE_FD); }

#define STATIC static
  // Clone is special as it needs a wrapper in syscall_table.c
  STATIC int sandbox_clone(int flags, void* stack, int* pid, int* ctid,
                           void* tls,void* wrapper_s) asm("sandbox__clone");
#else
#define STATIC
  STATIC int sandbox_clone(int flags, void* stack, int* pid, int* ctid,
                           void* tls);
#endif
  STATIC int sandbox_getpid()                          asm("sandbox_getpid");
  STATIC int sandbox_ioctl(int d, int req, void* arg)  asm("sandbox_ioctl");
  STATIC void *sandbox_mmap(void* start, size_t length, int prot, int flags,
                            int fd, off_t offset)      asm("sandbox_mmap");
  STATIC int sandbox_mprotect(const void*, size_t, int)asm("sandbox_mprotect");
  STATIC int sandbox_munmap(void* start, size_t lengt) asm("sandbox_munmap");
  STATIC int sandbox_open(const char*, int, mode_t)    asm("sandbox_open");
  STATIC int sandbox_stat(const char* path, void* buf) asm("sandbox_stat");
  #if __WORDSIZE == 32
  STATIC int sandbox_stat64(const char *path, void* b) asm("sandbox_stat64");
  #endif

  STATIC void thread_clone(int, pid_t, int, char*)     asm("thread_clone");
  STATIC void thread_getpid(int, pid_t, int, char*)    asm("thread_getpid");
  STATIC void thread_ioctl(int, pid_t, int, char*)     asm("thread_ioctl");
  STATIC void thread_mmap(int, pid_t, int, char*)      asm("thread_mmap");
  STATIC void thread_mprotect(int, pid_t, int, char*)  asm("thread_mprotect");
  STATIC void thread_munmap(int, pid_t, int, char*)    asm("thread_munmap");
  STATIC void thread_open(int, pid_t, int, char*)      asm("thread_open");
  STATIC void thread_stat(int, pid_t, int, char*)      asm("thread_stat");

  STATIC void process_clone(int, int, int, int, char*) asm("process_clone");
  STATIC void process_getpid(int, int, int, int, char*)asm("process_getpid");
  STATIC void process_ioctl(int, int, int, int, char*) asm("process_ioctl");
  STATIC void process_mmap(int, int, int, int, char*)  asm("process_mmap");
  STATIC void process_mprotect(int, int, int,int,char*)asm("process_mprotect");
  STATIC void process_munmap(int, int, int, int, char*)asm("process_munmap");
  STATIC void process_open(int, int, int, int, char*)  asm("process_open");
  STATIC void process_stat(int, int, int, int, char*)  asm("process_stat");

#ifdef __cplusplus
  class SysCalls {
   public:
    #define SYS_CPLUSPLUS
    #define SYS_ERRNO     my_errno
    #define SYS_INLINE    inline
    #define SYS_PREFIX    -1
    #undef  SYS_LINUX_SYSCALL_SUPPORT_H
    #include "linux_syscall_support.h"
    // TODO(markus): remove
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

  // TODO(markus): remove
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
    int*  ctid;
    void* tls;
    #if __WORDSIZE == 64
      struct {
        void* r15;
        void* r14;
        void* r13;
        void* r12;
        void* r11;
        void* r10;
        void* r9;
        void* r8;
        void *rbp;
        void* rdi;
        void* rsi;
        void* rdx;
        void* rcx;
        void *rbx;
        void* ret;
      } regs64 __attribute__((packed));
    #else
      struct {
// TODO(markus): if we touch other registers while setting up the new thread, we have to save them here
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
      SysCalls sys;
      sys.write(2, msg, strlen(msg));
      sys.write(2, "\n", 1);
    }
    _exit(1);
  }
  static char* secureCradle() { return secureCradle_; }

  static int read(SysCalls& sys, int fd, void *buf, ssize_t len) {
    if (len < 0) {
      sys.my_errno = EINVAL;
      return -1;
    }
    int offset = 0;
    while (offset < len) {
      int partial =
          NOINTR_SYS(sys.read(fd, reinterpret_cast<char *>(buf) + offset,
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

  static int write(SysCalls& sys, int fd, const void *buf, size_t len){
    return NOINTR_SYS(sys.write(fd, buf, len));
  }

  static bool sendFd(int transport, int fd0, int fd1 = -1,
                     void *buf = NULL, ssize_t len = -1);

  // If getFd() fails, it will set the first valid fd slot (e.g. fd0) to
  // -errno.
  static bool getFd(int transport, int* fd0, int* fd1 = 0,
                    void* buf = NULL, ssize_t* len = NULL);

  static void trustedThread(void *args) __attribute__((noreturn));

  static void (*getTrustedThreadFnc())();
  static void (*getTrustedThreadReturnResult())(void *);

  static ProtectedMap protectedMap_; // available in trusted process, only

 private:
  struct ChildArgs {
   public:
    template<int n>static ChildArgs* pushArgs(char (&stack)[n], char* mem,
                                              int fd0, int fd1, int fd2,
                                              int fd3, int fd4, int tid) {
      ChildArgs *args =
          reinterpret_cast<ChildArgs *>(stack + n - sizeof(ChildArgs));
      args->mem       = mem;
      args->fd0       = fd0;
      args->fd1       = fd1;
      args->fd2       = fd2;
      args->fd3       = fd3;
      args->fd4       = fd4;
      args->tid       = tid;
      return args;
    }
    char* mem;
    int   fd0, fd1, fd2, fd3, fd4;
    int   tid;
  };

  static void* defaultSystemCallHandler(int syscallNum, void *arg0, void *arg1,
                                        void *arg2, void *arg3, void *arg4,
                                        void *arg5);
  static void initializeProtectedMap(int fd);
  static void trustedProcess(void *args) __attribute__((noreturn));
  static void createTrustedProcess(int* fds, char* mem);
  static void createTrustedThread(int* fds, char* mem);
  static void snapshotMemoryMappings(int processFd);

  static char  stack_[8192];
  static int   pid_;
  static char* secureCradle_;
};

} // namespace

using playground::Sandbox;
#endif // __cplusplus

#endif // SANDBOX_IMPL_H__
