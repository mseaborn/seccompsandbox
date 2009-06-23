#include <sys/types.h>

struct SyscallTable *syscallTableAddr;
int                 syscallTableSize;
void                *defaultSystemCallHandler;

// clone.cc makes assumptions about the layout of the stack after
// being called through syscallWrapper(). If you change the layout, you
// will have to edit clone.cc.
__asm__(
    ".pushsection .text, \"ax\", @progbits\n"
    "syscallWrapper:"
    ".globl syscallWrapper\n"
    ".type syscallWrapper, @function\n"
    #if __WORDSIZE == 64
    // Save registers that are normally preserved by system calls
    "push %rcx\n"
    "push %rdx\n"
    "push %rsi\n"
    "push %rdi\n"
    "push %r8\n"
    "push %r9\n"
    "push %r10\n"
    "push %r11\n"

    // Convert from syscall calling conventions to C calling conventions
    "mov %r10, %rcx\n"

    // Check range of system call
    "cmp syscallTableSize(%rip), %eax\n"
    "ja  1f\n"

    // Retrieve function call from system call table
    "mov %rax, %r10\n"
    "shl $3, %r10\n"
    "mov %r10, %r11\n"
    "shl $1, %r10\n"
    "add %r11, %r10\n"
    "add syscallTableAddr(%rip), %r10\n"
    "mov 0(%r10), %r10\n"

    // Jump to function if non-null, otherwise jump to fallback handler
    "test %r10, %r10\n"
    "jz 1f\n"
    "call *%r10\n"
  "0:"

    // Restore CPU registers
    "pop %r11\n"
    "pop %r10\n"
    "pop %r9\n"
    "pop %r8\n"
    "pop %rdi\n"
    "pop %rsi\n"
    "pop %rdx\n"
    "pop %rcx\n"

    // Return to caller
    "ret\n"

  "1:"
    // Shift registers so that the system call number becomes visible as the
    // first function argument.
    "push %r9\n"
    "mov  %r8, %r9\n"
    "mov  %rcx, %r8\n"
    "mov  %rdx, %rcx\n"
    "mov  %rsi, %rdx\n"
    "mov  %rdi, %rsi\n"
    "mov  %rax, %rdi\n"

    // Call default handler.
    "call 2f\n"
  "2:addq $3f-2b, 0(%rsp)\n"
    "push defaultSystemCallHandler(%rip)\n"
    "ret\n"
  "3:pop  %r9\n"
    "jmp 0b\n"
    #else
    // Preserve all registers
    "push %ebx\n"
    "push %ecx\n"
    "push %edx\n"
    "push %esi\n"
    "push %edi\n"
    "push %ebp\n"

    // Convert from syscall calling conventions to C calling conventions
    "push %ebp\n"
    "push %edi\n"
    "push %esi\n"
    "push %edx\n"
    "push %ecx\n"
    "push %ebx\n"
    "push %eax\n"

    // Check range of system call
    "cmp syscallTableSize, %eax\n"
    "ja  1f\n"

    // Retrieve function call from system call table
    "shl  $2, %eax\n"
    "mov  %eax, %ebx\n"
    "shl  $1, %eax\n"
    "add  %ebx, %eax\n"
    "add  syscallTableAddr, %eax\n"
    "mov  0(%eax), %eax\n"

    // Jump to function if non-null, otherwise jump to fallback handler
    "test %eax, %eax\n"
    "jz   1f\n"
    "add  $4, %esp\n"
    "call *%eax\n"
    "add  $24, %esp\n"
  "0:"

    // Restore CPU registers
    "pop  %ebp\n"
    "pop  %edi\n"
    "pop  %esi\n"
    "pop  %edx\n"
    "pop  %ecx\n"
    "pop  %ebx\n"

    // Return to caller
    "ret\n"

  "1:"
    // Call default handler.
    "push $2f\n"
    "push defaultSystemCallHandler\n"
    "ret\n"
  "2:add  $28, %esp\n"
    "jmp 0b\n"

    #endif
    ".size syscallWrapper, .-syscallWrapper\n"
    ".popsection\n"
);
