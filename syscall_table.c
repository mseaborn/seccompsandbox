#include <asm/unistd.h>
#include "sandbox_impl.h"
#include "syscall_table.h"

#if defined(__x86_64__)
#ifndef __NR_set_robust_list
#define __NR_set_robust_list 273
#endif
#elif defined(__i386__)
#ifndef __NR_set_robust_list
#define __NR_set_robust_list 311
#endif
#else
#error Unsupported target platform
#endif

// TODO(markus): This is an incredibly dirty hack to make the syscallTable live in r/o memory
const struct SyscallTable syscallTable[] __attribute__((section(".rodata, \"a\", @progbits\n#"))) ={
  [ __NR_brk             ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_close           ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_clone           ] = { (void *)&sandbox_clone,    process_clone     },
  [ __NR_exit            ] = { (void *)&sandbox_exit,     process_exit      },
  [ __NR_exit_group      ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_fcntl           ] = { UNRESTRICTED_SYSCALL,      0                 },
  #if defined(__i386__)
  [ __NR_fcntl64         ] = { UNRESTRICTED_SYSCALL,      0                 },
  #endif
  [ __NR_fstat           ] = { UNRESTRICTED_SYSCALL,      0                 },
  #if defined(__i386__)
  [ __NR_fstat64         ] = { UNRESTRICTED_SYSCALL,      0                 },
  #endif
  [ __NR_futex           ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_getdents        ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_getdents64      ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_getpid          ] = { (void *)&sandbox_getpid,   0                 },
  [ __NR_gettimeofday    ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_ioctl           ] = { (void *)&sandbox_ioctl,    process_ioctl     },
  #if defined(__x86_64__)
  [ __NR_mmap            ] =
  #elif defined(__i386__)
  [ __NR_mmap2           ] =
  #else
  #error Unsupported target platform
  #endif
                             { (void *)&sandbox_mmap,     process_mmap      },
  [ __NR_mprotect        ] = { (void *)&sandbox_mprotect, process_mprotect  },
  [ __NR_munmap          ] = { (void *)&sandbox_munmap,   process_munmap    },
  [ __NR_open            ] = { (void *)&sandbox_open,     process_open      },
  [ __NR_set_robust_list ] = { UNRESTRICTED_SYSCALL,      0                 },
  [ __NR_stat            ] = { (void *)&sandbox_stat,     process_stat      },
  #if defined(__i386__)
  [ __NR_stat64          ] = { (void *)&sandbox_stat64,   process_stat      },
  #endif
};
const unsigned maxSyscall __attribute__((section(".rodata"))) = sizeof(syscallTable)/sizeof(struct SyscallTable);
