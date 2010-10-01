// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SYSCALL_TABLE_H__
#define SYSCALL_TABLE_H__

#include <sys/types.h>

// syscall_table.c has to be implemented in C, as C++ does not support
// designated initializers for arrays. The only other alternative would be
// to have a source code generator for this table.
//
// We would still like the C source file to include our header file. This
// requires some define statements to transform C++ specific constructs to
// something that is palatable to a C compiler.
#ifdef __cplusplus
#include "securemem.h"
extern "C" {
namespace playground {
  typedef SecureMem::Args SecureMemArgs;
  typedef SecureMem::SyscallRequestInfo SyscallRequestInfo;
#else
  typedef void SecureMemArgs;
  typedef void SyscallRequestInfo;
  typedef int bool;
#endif
  #define UNRESTRICTED_SYSCALL ((void *)1)

  struct SyscallTable {
    void   *handler;
    bool  (*trustedProcess)(const SyscallRequestInfo* info);
  };
  extern const struct SyscallTable syscallTable[]
    asm("playground$syscallTable")
#if defined(__x86_64__)
    __attribute__((visibility("internal")))
#endif
    ;
  extern const unsigned maxSyscall
    asm("playground$maxSyscall")
#if defined(__x86_64__)
    __attribute__((visibility("internal")))
#endif
    ;
#ifdef __cplusplus
} // namespace
}
#endif

#endif // SYSCALL_TABLE_H__
