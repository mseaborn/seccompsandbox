// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

        .global playground$runTrustedThread
playground$runTrustedThread:
        push %rbx
        push %rbp
        mov  %rdi, %rbp          // %rbp = args
        xor  %rbx, %rbx          // initial sequence number
        lea  999f(%rip), %r15    // continue in same thread
        xor  %rax, %rax
        movw %ax, %gs            // invalidate %gs

        // Signal handlers are process-wide. This means that for security
        // reasons, we cannot allow that the trusted thread ever executes any
        // signal handlers.
        // We prevent the execution of signal handlers by setting a signal
        // mask that blocks all signals. In addition, we make sure that the
        // stack pointer is invalid.
        // We cannot reset the signal mask until after we have enabled
        // Seccomp mode. Our sigprocmask() wrapper would normally do this by
        // raising a signal, modifying the signal mask in the kernel-generated
        // signal frame, and then calling sigreturn(). This presents a bit of
        // a Catch-22, as all signals are masked and we can therefore not
        // raise any signal that would allow us to generate the signal stack
        // frame.
        // Instead, we have to create the signal stack frame prior to entering
        // Seccomp mode. This incidentally also helps us to restore the
        // signal mask to the same value that it had prior to entering the
        // sandbox.
        // The signal wrapper for clone() is the second entry point into this
        // code (by means of sending an IPC to its trusted thread). It goes
        // through the same steps of creating a signal stack frame on the
        // newly created thread's stacks prior to cloning. See clone.cc for
        // details.
        mov  $56+0xF000, %eax    // __NR_clone + 0xF000
        mov  %rsp, %rcx
        int  $0                  // push a signal stack frame (see clone.cc)
        mov  %rcx, 0xA0(%rsp)    // pop stack upon call to sigreturn()
        mov  %rsp, %r9
        mov  $2, %rdi            // how     = SIG_SETMASK
        pushq $-1
        mov  %rsp, %rsi          // set     = full mask
        xor  %rdx, %rdx          // old_set = NULL
        mov  $8, %r10            // mask all 64 signals
        mov  $14, %eax           // NR_rt_sigprocmask
        syscall
        xor  %rsp, %rsp          // invalidate the stack in all trusted code
        jmp  20f                 // create trusted thread

        // TODO(markus): Coalesce the read() operations by reading into a bigger
        // buffer.

        // Parameters:
        //   *%fs: secure memory region
        //         the page following this one contains the scratch space
        //   %r13: thread's side of threadFd
        //   %r15: processFdPub

        // Local variables:
        //   %rbx: sequence number for trusted calls

        // Temporary variables:
        //   %r8: child stack
        //   %r9: system call number, child stack
        //  %rbp: secure memory of previous thread

        // Layout of secure shared memory region (c.f. securemem.h):
        //   0x00: pointer to the secure shared memory region (i.e. self)
        //   0x08: sequence number; must match %rbx
        //   0x10: call type; must match %eax, iff %eax == -1 || %eax == -2
        //   0x18: system call number; passed to syscall in %rax
        //   0x20: first argument; passed to syscall in %rdi
        //   0x28: second argument; passed to syscall in %rsi
        //   0x30: third argument; passed to syscall in %rdx
        //   0x38: fourth argument; passed to syscall in %r10
        //   0x40: fifth argument; passed to syscall in %r8
        //   0x48: sixth argument; passed to syscall in %r9
        //   0x50: stored return address for clone() system call
        //   0x58: stored %rbp value for clone() system call
        //   0x60: stored %rbx value for clone() system call
        //   0x68: stored %rcx value for clone() system call
        //   0x70: stored %rdx value for clone() system call
        //   0x78: stored %rsi value for clone() system call
        //   0x80: stored %rdi value for clone() system call
        //   0x88: stored %r8 value for clone() system call
        //   0x90: stored %r9 value for clone() system call
        //   0x98: stored %r10 value for clone() system call
        //   0xA0: stored %r11 value for clone() system call
        //   0xA8: stored %r12 value for clone() system call
        //   0xB0: stored %r13 value for clone() system call
        //   0xB8: stored %r14 value for clone() system call
        //   0xC0: stored %r15 value for clone() system call
        //   0xC8: new shared memory for clone()
        //   0xD0: processFdPub for talking to trusted process
        //   0xD4: cloneFdPub for talking to trusted process
        //   0xD8: set to non-zero, if in debugging mode
        //   0xDC: most recent SHM id returned by shmget(IPC_PRIVATE)
        //   0xE0: cookie assigned to us by the trusted process (TLS_COOKIE)
        //   0xE8: thread id (TLS_TID)
        //   0xF0: threadFdPub (TLS_THREAD_FD)
        //   0x200-0x1000: securely passed verified file name(s)

        // Layout of (untrusted) scratch space:
        //   0x00: syscall number; passed in %rax
        //   0x04: first argument; passed in %rdi
        //   0x0C: second argument; passed in %rsi
        //   0x14: third argument; passed in %rdx
        //   0x1C: fourth argument; passed in %r10
        //   0x24: fifth argument; passed in %r8
        //   0x2C: sixth argument; passed in %r9
        //   0x34: return value
        //   0x3C: RDTSCP result (%eax)
        //   0x40: RDTSCP result (%edx)
        //   0x44: RDTSCP result (%ecx)
        //   0x48: last system call (not used on x86-64)
        //   0x4C: number of consecutive calls to a time fnc (not used on x86-64)
        //   0x50: nesting level of system calls (for debugging purposes only)
        //   0x54: signal mask
        //   0x5C: in SEGV handler

        // We use the %fs register for accessing the secure read-only page, and
        // the untrusted scratch space immediately following it. The segment
        // register and the local descriptor table is set up by passing
        // appropriate arguments to clone().

      0:xor  %rsp, %rsp
        mov  $2, %ebx            // %rbx  = initial sequence number

        // Read request from untrusted thread, or from trusted process. In either
        // case, the data that we read has to be considered untrusted.
        // read(threadFd, &scratch, 4)
      1:xor  %rax, %rax          // NR_read
        mov  %r13, %rdi          // fd  = threadFd
        mov  %fs:0x0, %rsi       // secure_mem
        add  $0x1000, %rsi       // buf = &scratch
        mov  $4, %edx            // len = 4
      2:syscall
        cmp  $-4, %rax           // EINTR
        jz   2b
        cmp  %rdx, %rax
        jnz  fatal_error

        // Retrieve system call number. It is crucial that we only dereference
        // %fs:0x1000 exactly once. Afterwards, memory becomes untrusted and
        // we must use the value that we have read the first time.
        mov  0(%rsi), %eax

        // If syscall number is -1, execute an unlocked system call from the
        // secure memory area
        cmp  $-1, %eax
        jnz  5f
      3:cmp  %rbx, %fs:0x8
        jne  fatal_error
        cmp  %fs:0x10, %eax
        jne  fatal_error
        mov  %fs:0x18, %rax
        mov  %fs:0x20, %rdi
        mov  %fs:0x28, %rsi
        mov  %fs:0x30, %rdx
        mov  %fs:0x38, %r10
        mov  %fs:0x40, %r8
        mov  %fs:0x48, %r9
        cmp  %rbx, %fs:0x8
        jne  fatal_error
        add  $2, %rbx

        // shmget() gets some special treatment. Whenever we return from this
        // system call, we remember the most recently returned SysV shm id.
        cmp  $29, %eax           // NR_shmget
        jnz  4f
        syscall
        mov  %rax, %r8
        mov  $56, %eax           // NR_clone
        mov  $17, %edi           // flags = SIGCHLD
        mov  $1, %esi            // stack = 1
        syscall
        test %rax, %rax
        js   fatal_error
        mov  %rax, %rdi
        jnz  8f                  // wait for child, then return result
        mov  %fs:0x0, %rdi       // start = secure_mem
        mov  $4096, %esi         // len   = 4096
        mov  $3, %edx            // prot  = PROT_READ | PROT_WRITE
        mov  $10, %eax           // NR_mprotect
        syscall
        mov  %r8d, 0xDC(%rdi)    // set most recently returned SysV shm id
        xor  %rdi, %rdi

        // When debugging messages are enabled, warn about expensive system calls
        #ifndef NDEBUG
        cmpw $0, %fs:0xD8        // debug mode
        jz   27f
        mov  $1, %eax            // NR_write
        mov  $2, %edi            // fd = stderr
        lea  101f(%rip), %rsi    // "This is an expensive system call"
        mov  $102f-101f, %edx    // len = strlen(msg)
        syscall
        xor  %rdi, %rdi
        #endif

        jmp  27f                 // exit program, no message
      4:syscall
        jmp  15f                 // return result

        // If syscall number is -2, execute locked system call from the
        // secure memory area
      5:jg   12f
        cmp  $-2, %eax
        jnz  9f
        cmp  %rbx, %fs:0x8
        jne  fatal_error
        cmp  %eax, %fs:0x10
        jne  fatal_error

        // When debugging messages are enabled, warn about expensive system calls
        #ifndef NDEBUG
        cmpw $0, %fs:0xD8        // debug mode
        jz   6f
        mov  $1, %eax            // NR_write
        mov  $2, %edi            // fd = stderr
        lea  101f(%rip), %rsi    // "This is an expensive system call"
        mov  $102f-101f, %edx    // len = strlen(msg)
        syscall
      6:
        #endif

        mov  %fs:0x18, %rax
        mov  %fs:0x20, %rdi
        mov  %fs:0x28, %rsi
        mov  %fs:0x30, %rdx
        mov  %fs:0x38, %r10
        mov  %fs:0x40, %r8
        mov  %fs:0x48, %r9
        cmp  %rbx, %fs:0x8
        jne  fatal_error

        // clone() has unusual calling conventions and must be handled specially
        cmp  $56, %rax           // NR_clone
        jz   19f

        // exit() terminates trusted thread
        cmp  $60, %eax           // NR_exit
        jz   18f

        // Perform requested system call
        syscall

        // Unlock mutex
      7:cmp  %rbx, %fs:0x8
        jne  fatal_error
        add  $2, %rbx
        mov  %rax, %r8
        mov  $56, %eax           // NR_clone
        mov  $17, %rdi           // flags = SIGCHLD
        mov  $1, %rsi            // stack = 1
        syscall
        test %rax, %rax
        js   fatal_error
        jz   22f                 // unlock and exit
        mov  %rax, %rdi
      8:xor  %rsi, %rsi
        xor  %rdx, %rdx
        xor  %r10, %r10
        mov  $61, %eax           // NR_wait4
        syscall
        cmp  $-4, %eax           // EINTR
        jz   8b
        mov  %r8, %rax
        jmp  15f                 // return result

        // If syscall number is -3, read the time stamp counter
      9:cmp  $-3, %eax
        jnz  10f
        rdtsc                    // sets %edx:%eax
        xor  %rcx, %rcx
        jmp  11f
      10:cmp  $-4, %eax
        jnz  12f
        rdtscp                   // sets %edx:%eax and %ecx
     11:add  $0x3C, %rsi
        mov  %eax, 0(%rsi)
        mov  %edx, 4(%rsi)
        mov  %ecx, 8(%rsi)
        mov  $12, %edx
        jmp  16f                 // return result

        // Check in syscallTable whether this system call is unrestricted
     12:mov  %rax, %r9
        #ifndef NDEBUG
        cmpw $0, %fs:0xD8        // debug mode
        jnz  13f
        #endif
        cmp  playground$maxSyscall(%rip), %eax
        ja   fatal_error
        shl  $4, %rax
        lea  playground$syscallTable(%rip), %rdi
        add  %rdi, %rax
        mov  0(%rax), %rax
        cmp  $1, %rax
        jne  fatal_error

        // Default behavior for unrestricted system calls is to just execute
        // them. Read the remaining arguments first.
     13:mov  %rsi, %r8
        xor  %rax, %rax          // NR_read
        mov  %r13, %rdi          // fd  = threadFd
        add  $4, %rsi            // buf = &scratch + 4
        mov  $48, %edx           // len = 6*sizeof(void *)
     14:syscall
        cmp  $-4, %rax           // EINTR
        jz   14b
        cmp  %rdx, %rax
        jnz  fatal_error
        mov  %r9, %rax
        mov  0x04(%r8), %rdi
        mov  0x0C(%r8), %rsi
        mov  0x14(%r8), %rdx
        mov  0x1C(%r8), %r10
        mov  0x2C(%r8), %r9
        mov  0x24(%r8), %r8
        cmp  $231, %rax          // NR_exit_group
        jz   27f                 // exit program, no message
        syscall

        // Return result of system call to sandboxed thread
     15:mov  %fs:0x0, %rsi       // secure_mem
        add  $0x1034, %rsi       // buf   = &scratch + 52
        mov  %rax, (%rsi)
        mov  $8, %edx            // len   = 8
     16:mov  %r13, %rdi          // fd    = threadFd
        mov  $1, %eax            // NR_write
     17:syscall
        cmp  %rdx, %rax
        jz   1b
        cmp  $-4, %rax           // EINTR
        jz   17b
        jmp  fatal_error

        // NR_exit:
        // Exit trusted thread after cleaning up resources
     18:mov  %fs:0x0, %rsi       // secure_mem
        mov  0xF0(%rsi), %rdi    // fd     = threadFdPub
        mov  $3, %eax            // NR_close
        syscall
        mov  %rsi, %rdi          // start  = secure_mem
        mov  $8192, %esi         // length = 8192
        xor  %rdx, %rdx          // prot   = PROT_NONE
        mov  $10, %eax           // NR_mprotect
        syscall
        mov  %r13, %rdi          // fd     = threadFd
        mov  $3, %eax            // NR_close
        syscall
        mov  $56, %eax           // NR_clone
        mov  $17, %rdi           // flags = SIGCHLD
        mov  $1, %rsi            // stack = 1
        syscall
        mov  %rax, %rdi
        test %rax, %rax
        js   27f                 // exit process
        jne  21f                 // reap helper, exit thread
        jmp  22f                 // unlock mutex

        // NR_clone:
        // Original trusted thread calls clone() to create new nascent
        // thread. This thread is (typically) fully privileged and shares all
        // resources with the caller (i.e. the previous trusted thread),
        // and by extension it shares all resources with the sandbox'd
        // threads.
     19:mov  %fs:0x0, %rbp       // %rbp  = old_shared_mem
        mov  %rsi, %r15          // remember child stack
        mov  $1, %rsi            // stack = 1
        syscall                  // calls NR_clone
        cmp  $-4095, %rax        // return codes -1..-4095 are errno values
        jae  7b                  // unlock mutex, return result
        add  $2, %rbx
        test %rax, %rax
        jne  15b                 // return result

        // In nascent thread, now.
        sub  $2, %rbx

        // We want to maintain an invalid %rsp whenver we access untrusted
        // memory. This ensures that even if an attacker can trick us into
        // triggering a SIGSEGV, we will never successfully execute a signal
        // handler.
        // Signal handlers are inherently dangerous, as an attacker could trick
        // us into returning to the wrong address by adjusting the signal stack
        // right before the handler returns.
        // N.B. While POSIX is curiously silent about this, it appears that on
        // Linux, alternate signal stacks are a per-thread property. That is
        // good. It means that this security mechanism works, even if the
        // sandboxed thread manages to set up an alternate signal stack.
        //
        // TODO(markus): We currently do not support emulating calls to
        // sys_clone() with a zero (i.e. copy) stack parameter. See clone.cc
        // for a discussion on how to fix this, if this ever becomes neccessary.
        mov  %r15, %r9           // %r9 = child_stack
        xor  %r15, %r15          // Request to return from clone() when done

        // Get thread id of nascent thread
     20:mov  $186, %eax          // NR_gettid
        syscall
        mov  %rax, %r14

        // Nascent thread creates socketpair() for sending requests to
        // trusted thread.
        // We can create the filehandles on the child's stack. Filehandles are
        // always treated as untrusted.
        // socketpair(AF_UNIX, SOCK_STREAM, 0, fds)
        sub  $0x10, %r9
        mov  %r15, 8(%r9)        // preserve return address on child stack
        mov  $53, %eax           // NR_socketpair
        mov  $1, %edi            // domain = AF_UNIX
        mov  $1, %esi            // type = SOCK_STREAM
        xor  %rdx, %rdx          // protocol = 0
        mov  %r9, %r10           // sv = child_stack
        syscall
        test %rax, %rax
        jz   28f

        // If things went wrong, we don't have an (easy) way of signaling
        // the parent. For our purposes, it is sufficient to fail with a
        // fatal error.
        jmp  fatal_error
     21:xor  %rsi, %rsi
        xor  %rdx, %rdx
        xor  %r10, %r10
        mov  $61, %eax           // NR_wait4
        syscall
        cmp  $-4, %eax           // EINTR
        jz   21b
        jmp  23f                 // exit thread (no message)
     22:lea  playground$syscall_mutex(%rip), %rdi
        mov  $4096, %esi
        mov  $3, %edx            // prot = PROT_READ | PROT_WRITE
        mov  $10, %eax           // NR_mprotect
        syscall
        lock; addl $0x80000000, (%rdi)
        jz   23f                 // exit thread
        mov  $1, %edx
        mov  %rdx, %rsi          // FUTEX_WAKE
        mov  $202, %eax          // NR_futex
        syscall
     23:mov  $60, %eax           // NR_exit
        mov  $1, %edi            // status = 1
     24:syscall
fatal_error:
        mov  $1, %eax            // NR_write
        mov  $2, %edi            // fd = stderr
        lea  100f(%rip), %rsi    // "Sandbox violation detected"
        mov  $101f-100f, %edx    // len = strlen(msg)
        syscall
     26:mov  $1, %edi
     27:mov  $231, %eax          // NR_exit_group
        jmp  24b

        // The first page is mapped read-only for use as securely shared memory
     28:mov  0xC8(%rbp), %r12    // %r12 = secure shared memory
        cmp  %rbx, 8(%rbp)
        jne  fatal_error
        mov  $10, %eax           // NR_mprotect
        mov  %r12, %rdi          // addr = secure_mem
        mov  $4096, %esi         // len  = 4096
        mov  $1, %edx            // prot = PROT_READ
        syscall

        // The second page is used as scratch space by the trusted thread.
        // Make it writable.
        mov  $10, %eax           // NR_mprotect
        add  $4096, %rdi         // addr = secure_mem + 4096
        mov  $3, %edx            // prot = PROT_READ | PROT_WRITE
        syscall

        // Call clone() to create new trusted thread().
        // clone(CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|
        //       CLONE_SYSVSEM|CLONE_UNTRACED|CLONE_SETTLS, stack, NULL, NULL,
        //       tls)
        mov  4(%r9), %r13d       // %r13  = threadFd (on child's stack)
        mov  $56, %eax           // NR_clone
        mov  $0x8D0F00, %edi     // flags = VM|FS|FILES|SIGH|THR|SYSV|UTR|TLS
        mov  $1, %rsi            // stack = 1
        mov  %r12, %r8           // tls   = new_secure_mem
        mov  0xD0(%rbp), %r15d   // %r15  = processFdPub
        cmp  %rbx, 8(%rbp)
        jne  fatal_error
        syscall
        test %rax, %rax
        js   fatal_error
        jz   0b                  // invoke trustedThreadFnc()

        // Copy the caller's signal mask
        mov  0x1054(%rbp), %rax
        mov  %rax, 0x1054(%r12)

        // Done creating trusted thread. We can now get ready to return to caller
        mov  %r9, %r8            // %r8 = child_stack
        mov  0(%r9), %r9d        // %r9 = threadFdPub

        // Set up thread local storage with information on how to talk to
        // trusted thread and trusted process.
        lea  0xE0(%r12), %rsi    // args   = &secure_mem.TLS;
        mov  $158, %eax          // NR_arch_prctl
        mov  $0x1001, %edi       // option = ARCH_SET_GS
        syscall
        cmp  $-4095, %rax        // return codes -1..-4095 are errno values
        jae  fatal_error

        // Check whether this is the initial thread, or a newly created one.
        // At startup we run the same code as when we create a new thread. At
        // the very top of this function, you will find that we push 999(%rip)
        // on the stack. That is the signal that we should return on the same
        // stack rather than return to where clone was called.
        mov  8(%r8), %r15
        add  $0x10, %r8
        test %r15, %r15
        jne  29f

        // Returning from clone() into the newly created thread is special. We
        // cannot unroll the stack, as we just set up a new stack for this
        // thread. We have to explicitly restore CPU registers to the values
        // that they had when the program originally called clone().
        // We patch the register values in the signal stack frame so that we
        // can ask sigreturn() to restore all registers for us.
        sub  $0x8, %r8
        mov  0x50(%rbp), %rax
        mov  %rax, 0x00(%r8)     // return address
        xor  %rax, %rax
        mov  %rax, 0x98(%r8)     // %rax = 0
        mov  0x58(%rbp), %rax
        mov  %rax, 0x80(%r8)     // %rbp
        mov  0x60(%rbp), %rax
        mov  %rax, 0x88(%r8)     // %rbx
        mov  0x68(%rbp), %rax
        mov  %rax, 0xA0(%r8)     // %rcx
        mov  0x70(%rbp), %rax
        mov  %rax, 0x90(%r8)     // %rdx
        mov  0x78(%rbp), %rax
        mov  %rax, 0x78(%r8)     // %rsi
        mov  0x80(%rbp), %rax
        mov  %rax, 0x70(%r8)     // %rdi
        mov  0x88(%rbp), %rax
        mov  %rax, 0x30(%r8)     // %r8
        mov  0x90(%rbp), %rax
        mov  %rax, 0x38(%r8)     // %r9
        mov  0x98(%rbp), %rax
        mov  %rax, 0x40(%r8)     // %r10
        mov  0xA0(%rbp), %rax
        mov  %rax, 0x48(%r8)     // %r11
        mov  0xA8(%rbp), %rax
        mov  %rax, 0x50(%r8)     // %r12
        mov  0xB0(%rbp), %rax
        mov  %rax, 0x58(%r8)     // %r13
        mov  0xB8(%rbp), %rax
        mov  %rax, 0x60(%r8)     // %r14
        mov  0xC0(%rbp), %rax
        mov  %rax, 0x68(%r8)     // %r15
        cmp  %rbx, 8(%rbp)
        jne  fatal_error

        // Nascent thread launches a helper that doesn't share any of our
        // resources, except for pages mapped as MAP_SHARED.
        // clone(SIGCHLD, stack=1)
     29:mov  $56, %eax           // NR_clone
        mov  $17, %rdi           // flags = SIGCHLD
        mov  $1, %rsi            // stack = 1
        syscall
        test %rax, %rax
        js   fatal_error
        jne  31f

        // Use sendmsg() to send to the trusted process the file handles for
        // communicating with the new trusted thread. We also send the address
        // of the secure memory area (for sanity checks) and the thread id.
        mov  0xD4(%rbp), %edi    // transport = Sandbox::cloneFdPub()
        cmp  %rbx, 8(%rbp)
        jne  fatal_error

        // 0x00 msg:
        //   0x00 msg_name       ($0)
        //   0x08 msg_namelen    ($0)
        //   0x10 msg_iov        (%r8 + 0x44)
        //   0x18 msg_iovlen     ($1)
        //   0x20 msg_control    (%r8 + 0x54)
        //   0x28 msg_controllen ($0x18)
        // 0x30 data:
        //   0x30 msg_flags/err  ($0)
        //   0x34 secure_mem     (%r12)
        //   0x3C threadId       (%r14d)
        //   0x40 threadFdPub    (%r9d)
        // 0x44 iov:
        //   0x44 iov_base       (%r8 + 0x30)
        //   0x4C iov_len        ($0x14)
        // 0x54 cmsg:
        //   0x54 cmsg_len       ($0x18)
        //   0x5C cmsg_level     ($1, SOL_SOCKET)
        //   0x60 cmsg_type      ($1, SCM_RIGHTS)
        //   0x64 threadFdPub    (%r9d)
        //   0x68 threadFd       (%r13d)
        // 0x6C
        sub  $0x6C, %r8
        xor  %rdx, %rdx          // flags = 0
        mov  %rdx, 0x00(%r8)     // msg_name
        mov  %edx, 0x08(%r8)     // msg_namelen
        mov  %edx, 0x30(%r8)     // msg_flags
        mov  $1, %r11d
        mov  %r11, 0x18(%r8)     // msg_iovlen
        mov  %r11d, 0x5C(%r8)    // cmsg_level
        mov  %r11d, 0x60(%r8)    // cmsg_type
        lea  0x30(%r8), %r11
        mov  %r11, 0x44(%r8)     // iov_base
        add  $0x14, %r11
        mov  %r11, 0x10(%r8)     // msg_iov
        add  $0x10, %r11
        mov  %r11, 0x20(%r8)     // msg_control
        mov  $0x14, %r11d
        mov  %r11, 0x4C(%r8)     // iov_len
        add  $4, %r11d
        mov  %r11, 0x28(%r8)     // msg_controllen
        mov  %r11, 0x54(%r8)     // cmsg_len
        mov  %r12, 0x34(%r8)     // secure_mem
        mov  %r14d, 0x3C(%r8)    // threadId
        mov  %r9d, 0x40(%r8)     // threadFdPub
        mov  %r9d, 0x64(%r8)     // threadFdPub
        mov  %r13d, 0x68(%r8)    // threadFd
        mov  $46, %eax           // NR_sendmsg
        mov  %r8, %rsi           // msg
        syscall

        // Release syscall_mutex_. This signals the trusted process that
        // it can write into the original thread's secure memory again.
        mov  $10, %eax           // NR_mprotect
        lea  playground$syscall_mutex(%rip), %rdi
        mov  $4096, %esi
        mov  $3, %edx            // PROT_READ | PROT_WRITE
        syscall
        cmp  %rbx, 8(%rbp)
        jne  fatal_error
        lock; addl $0x80000000, (%rdi)
        jz   30f                 // exit process (no error message)
        mov  $1, %edx
        mov  %rdx, %rsi          // FUTEX_WAKE
        mov  $202, %eax          // NR_futex
        syscall
     30:xor  %rdi, %rdi
        jmp  27b                 // exit process (no error message)

        // Reap helper
     31:mov  %rax, %rdi
     32:lea  -4(%r8), %rsi
        xor  %rdx, %rdx
        xor  %r10, %r10
        mov  $61, %eax           // NR_wait4
        syscall
        cmp  $-4, %eax           // EINTR
        jz   32b
        mov  -4(%r8), %eax
        test %rax, %rax
        jnz  26b                 // exit process (no error message)

        // Release privileges by entering seccomp mode.
        mov  $157, %eax          // NR_prctl
        mov  $22, %edi           // PR_SET_SECCOMP
        mov  $1, %esi
        syscall
        test %rax, %rax
        jnz  fatal_error

        // We can finally start using the stack. Signal handlers no longer pose
        // a threat to us.
        mov  %r8, %rsp

        // Back in the newly created sandboxed thread, wait for trusted process
        // to receive request. It is possible for an attacker to make us
        // continue even before the trusted process is done. This is OK. It'll
        // result in us putting stale values into the new thread's TLS. But that
        // data is considered untrusted anyway.
        push %rax
        mov  $1, %edx            // len       = 1
        mov  %rsp, %rsi          // buf       = %rsp
        mov  %r9, %rdi           // fd        = threadFdPub
     33:xor  %rax, %rax          // NR_read
        syscall
        cmp  $-4, %rax           // EINTR
        jz   33b
        cmp  %rdx, %rax
        jne  fatal_error
        pop  %rax

        // Return to caller. We are in the new thread, now.
        test %r15, %r15
        jnz  34f                 // Returning to createTrustedThread()

        // Returning to the place where clone() had been called. We rely on
        // using rt_sigreturn() for restoring our registers. The caller already
        // created a signal stack frame, and we patched the register values
        // with the ones that were in effect prior to calling sandbox_clone().
        pop %r15
     34:mov  %r15, 0xA8(%rsp)    // compute new %rip
        mov  $15, %eax           // NR_rt_sigreturn
        syscall

        .pushsection ".rodata"
    100:.ascii "Sandbox violation detected, program aborted\n"
    101:.ascii "WARNING! This is an expensive system call\n"
    102:
        .popsection

    999:pop  %rbp
        pop  %rbx
        ret
