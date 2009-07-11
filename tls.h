#ifndef TLS_H__
#define TLS_H__

#include <asm/ldt.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/prctl.h>

namespace playground {

class TLS {
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
  static void *allocateTLS() {
    SysCalls sys;
    #if __WORDSIZE == 64
      void *addr = sys.mmap(0, 4096, PROT_READ|PROT_WRITE,
                            MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
      if (sys.arch_prctl(ARCH_SET_GS, addr) < 0) {
        return NULL;
      }
    #else
      void *addr = sys.mmap2(0, 4096, PROT_READ|PROT_WRITE,
                             MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
      struct user_desc u;
      u.entry_number    = (typeof u.entry_number)-1;
      u.base_addr       = (int)addr;
      u.limit           = 0xfffff;
      u.seg_32bit       = 1;
      u.contents        = 0;
      u.read_exec_only  = 0;
      u.limit_in_pages  = 1;
      u.seg_not_present = 0;
      u.useable         = 1;
      if (sys.set_thread_area(&u) < 0) {
        return NULL;
      }
      asm("movw %w0, %%fs"
          :
          : "q"(8*u.entry_number+3));
    #endif
    return addr;
  }

  static void freeTLS() {
    SysCalls sys;
    void *addr;
    #if __WORDSIZE == 64
      sys.arch_prctl(ARCH_GET_GS, &addr);
    #else
      struct user_desc u;
      sys.get_thread_area(&u);
      addr = (void *)u.base_addr;
    #endif
    sys.munmap(addr, 4096);
  }

  template<class T> static inline bool setTLSValue(int idx, T val) {
    #if __WORDSIZE == 64
      if (idx < 0 || idx >= 4096/8) {
        return false;
      }
      asm("movq %0, %%gs:(%1)\n"
          :
          : "q"((void *)val), "q"(8ll * idx));
    #else
      if (idx < 0 || idx >= 4096/4) {
        return false;
      }
      asm("movl %0, %%fs:(%1)\n"
          :
          : "r"(val), "r"(4 * idx));
    #endif
    return true;
  }

  template<class T> static inline T getTLSValue(int idx) {
    #if __WORDSIZE == 64
      long long rc;
      if (idx < 0 || idx >= 4096/8) {
        return 0;
      }
      asm("movq %%gs:(%1), %0\n"
          : "=q"(rc)
          : "q"(8ll * idx));
    #else
      long rc;
      if (idx < 0 || idx >= 4096/4) {
        return 0;
      }
      asm("movl %%fs:(%1), %0\n"
          : "=r"(rc)
          : "r"(4 * idx));
    #endif
    return (T)rc;
  }

};

} // namespace
#endif
