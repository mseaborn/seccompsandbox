#ifndef MUTEX_H__
#define MUTEX_H__

#include <linux/futex.h>
#include "linux_syscall_support.h"

#define NOINTR_SYS(x)                                                         \
 ({ int i__; while ((i__ = (x)) < 0 && sys.my_errno == EINTR); i__;})

namespace playground {

class Mutex {
 private:
  class SysCalls {
   public:
    #define SYS_CPLUSPLUS
    #define SYS_ERRNO     my_errno
    #define SYS_INLINE    inline
    #define SYS_PREFIX    -1
    #undef  SYS_LINUX_SYSCALL_SUPPORT_H
    #include "linux_syscall_support.h"
    SysCalls() : my_errno(0) { }
    int my_errno;
  };

 public:
  typedef int mutex_t;

  enum { kInitValue = 0 };

  static void initMutex(mutex_t* mutex) {
    // Mutex is unlocked, and nobody is waiting for it
    *mutex = kInitValue;
  }

  static void unlockMutex(mutex_t* mutex) {
    char status;
    #if defined(__x86_64__) || defined(__i386__)
    asm volatile(
        "lock; addl %2, %0\n"
        "setz %1"
        : "=m"(*mutex), "=qm"(status)
        : "ir"(0x80000000), "m"(*mutex));
    #else
      #error Unsupported target platform
    #endif
    if (status) {
      // Mutex is zero now. No other waiters. So, we can return.
      return;
    }
    // We unlocked the mutex, but still need to wake up other waiters.
    SysCalls sys;
    sys.futex(mutex, FUTEX_WAKE, 1, NULL);
  }

  static bool lockMutex(mutex_t* mutex, int timeout = 0) {
    bool rc        = true;
    // Increment mutex to add ourselves to the list of waiters
    #if defined(__x86_64__) || defined(__i386__)
    asm volatile(
        "lock; incl %0\n"
        : "=m"(*mutex)
        : "m"(*mutex));
    #else
      #error Unsupported target platform
    #endif
    for (;;) {
      // Atomically check whether the mutex is available and if so, acquire it
      char status;
      #if defined(__x86_64__) || defined(__i386__)
      asm volatile(
          "lock; btsl %3, %1\n"
          "setc %0"
          : "=q"(status), "=m"(*mutex)
          : "m"(*mutex), "ir"(31));
      #else
        #error Unsupported target platform
      #endif
      if (!status) {
     done:
        // If the mutex was available, remove ourselves from list of waiters
        #if defined(__x86_64__) || defined(__i386__)
        asm volatile(
            "lock; decl %0\n"
            : "=m"(*mutex)
            : "m"(*mutex));
        #else
          #error Unsupported target platform
        #endif
        return rc;
      }
      int value    = *mutex;
      if (value >= 0) {
        // Mutex has just become available, no need to call kernel
        continue;
      }
      SysCalls sys;
      SysCalls::kernel_timespec tm;
      if (timeout) {
        tm.tv_sec  = timeout / 1000;
        tm.tv_nsec = (timeout % 1000) * 1000 * 1000;
      } else {
        tm.tv_sec  = 0;
        tm.tv_nsec = 0;
      }
      if (NOINTR_SYS(sys.futex(mutex, FUTEX_WAIT, value, &tm)) &&
          sys.my_errno == ETIMEDOUT) {
        rc         = false;
        goto done;
      }
    }
  }
};

} // namespace

#endif // MUTEX_H__
