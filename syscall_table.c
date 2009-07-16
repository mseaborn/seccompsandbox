#include <asm/unistd.h>
#include "sandbox_impl.h"
#include "syscall_table.h"

#if __WORDSIZE == 64
#ifndef __NR_set_robust_list
#define __NR_set_robust_list 273
#endif
#else
#ifndef __NR_set_robust_list
#define __NR_set_robust_list 311
#endif
#endif

// TODO(markus): This is an incredibly dirty hack to make the syscallTable live in r/o memory
const struct SyscallTable syscallTable[] __attribute__((section(".rodata, \"a\", @progbits\n#"))) ={
  [ __NR_brk             ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_close           ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_clone           ] = { (void *)&sandbox_clone,    0, process_clone   },
  [ __NR_exit            ] = { (void *)&sandbox_exit,     0, process_exit    },
  [ __NR_exit_group      ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_fcntl           ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  #if __WORDSIZE == 32
  [ __NR_fcntl64         ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  #endif
  [ __NR_fstat           ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  #if __WORDSIZE == 32
  [ __NR_fstat64         ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  #endif
  [ __NR_futex           ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_getdents        ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_getdents64      ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_getpid          ] = { (void *)&sandbox_getpid,   0, 0               },
  [ __NR_gettimeofday    ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_ioctl           ] = { (void *)&sandbox_ioctl,    0, process_ioctl   },
  #if __WORDSIZE == 64
  [ __NR_mmap            ] =
  #else
  [ __NR_mmap2           ] =
  #endif
                             { (void *)&sandbox_mmap,     0, process_mmap    },
  [ __NR_mprotect        ] = { (void *)&sandbox_mprotect, 0, process_mprotect},
  [ __NR_munmap          ] = { (void *)&sandbox_munmap,   0, process_munmap  },
  [ __NR_open            ] = { (void *)&sandbox_open,thread_open,process_open},
  [ __NR_set_robust_list ] = { UNRESTRICTED_SYSCALL, UNRESTRICTED_SYSCALL, 0 },
  [ __NR_stat            ] = { (void *)&sandbox_stat,thread_stat,process_stat},
  #if __WORDSIZE == 32
  [ __NR_stat64          ] = { (void *)&sandbox_stat64,
                               thread_stat,
                               process_stat },
  #endif
};

const unsigned maxSyscall __attribute__((section(".rodata"))) = sizeof(syscallTable)/sizeof(struct SyscallTable);
