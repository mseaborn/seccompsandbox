// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debug.h"
#include "sandbox_impl.h"

namespace playground {

long Sandbox::sandbox_mprotect(const void *addr, size_t len, int prot) {
  long long tm;
  Debug::syscall(&tm, __NR_mprotect, "Executing handler");
  struct {
    struct RequestHeader header;
    MProtect  mprotect_req;
  } __attribute__((packed)) request;
  request.mprotect_req.addr = addr;
  request.mprotect_req.len  = len;
  request.mprotect_req.prot = prot;

  long rc = forwardSyscall(__NR_mprotect, &request.header, sizeof(request));
  Debug::elapsed(tm, __NR_mprotect);
  return rc;
}

bool Sandbox::process_mprotect(const SecureMem::SyscallRequestInfo* info) {
  // Read request
  SysCalls sys;
  MProtect mprotect_req;
  if (read(sys, info->trustedProcessFd, &mprotect_req, sizeof(mprotect_req)) !=
      sizeof(mprotect_req)) {
    die("Failed to read parameters for mprotect() [process]");
  }

  // Cannot change permissions on any memory region that was part of the
  // original memory mappings.
  int rc = -EINVAL;
  void *stop = reinterpret_cast<void *>(
      (char *)mprotect_req.addr + mprotect_req.len);
  ProtectedMap::const_iterator iter = protectedMap_.lower_bound(
      (void *)mprotect_req.addr);
  if (iter != protectedMap_.begin()) {
    --iter;
  }
  for (; iter != protectedMap_.end() && iter->first < stop; ++iter) {
    if (mprotect_req.addr < reinterpret_cast<void *>(
            reinterpret_cast<char *>(iter->first) + iter->second) &&
        stop > iter->first) {
      SecureMem::abandonSystemCall(*info, rc);
      return false;
    }
  }

  // Changing permissions on memory regions that were newly mapped inside of
  // the sandbox is OK.
  SecureMem::sendSystemCall(*info, false, mprotect_req.addr, mprotect_req.len,
                            mprotect_req.prot);
  return true;
}

} // namespace
