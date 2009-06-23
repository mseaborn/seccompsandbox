#ifndef SYSCALL_H__
#define SYSCALL_H__

#ifdef __cplusplus
extern "C" {
#endif

extern struct SyscallTable *syscallTableAddr;
extern int                 syscallTableSize;
extern void                *defaultSystemCallHandler;

void syscallWrapper();

#ifdef __cplusplus
}
#endif

#endif // SYSCALL_H__
