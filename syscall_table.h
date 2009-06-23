#ifndef SYSCALL_TABLE_H__
#define SYSCALL_TABLE_H__

#ifdef __cplusplus
extern "C" {
#endif
  #define UNRESTRICTED_SYSCALL ((void *)-1)

  struct SyscallTable {
    void *handler;
    void *trustedThread;
    void (*trustedProcess)(int fd);
  };
  extern struct SyscallTable syscallTable[];
  unsigned maxSyscall(void);
#ifdef __cplusplus
}
#endif

#endif // SYSCALL_TABLE_H__
