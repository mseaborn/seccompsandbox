#ifndef SYSCALL_TABLE_H__
#define SYSCALL_TABLE_H__

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
  #define UNRESTRICTED_SYSCALL ((void *)-1)

  struct SyscallTable {
    void *handler;
    void (*trustedThread)(int processFd, pid_t tid, int threadFd, char* mem);
    void (*trustedProcess)(int sandboxFd, int processFd, int threadFd,
                           int cloneFd, char* mem);
  };
  extern const struct SyscallTable syscallTable[];
  extern const unsigned maxSyscall;
#ifdef __cplusplus
}
#endif

#endif // SYSCALL_TABLE_H__
