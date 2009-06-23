#include "sandbox_impl.h"
#include "securemem.h"

#define NOINTR(x) ({ int i__; while ((i__ = (x)) < 0 && errno == EINTR); i__;})

namespace playground {

int SecureMem::mktmpfd(const char *prefix) {
  int l = strlen(prefix);
  char filename[l + 7];
  memset(filename, 0, l + 7);
  strcpy(filename, prefix);
  struct timeval tv;
  gettimeofday(&tv, NULL);
  unsigned long long rnd = ((unsigned long long)tv.tv_usec << 16) & tv.tv_sec;
  for (int i = 0; i < 100; i++, rnd += getpid()) {
    // Try creating a uniquely named file. Make sure that nobody else opens the
    // same file and keep trying if we happen to find a collision in the
    // filename. We could have used mkstemp(), but that function can be tricked
    // into following symbolic links.
    unsigned long long r = rnd;
    for (int j = 0; j < 6; j++) {
      filename[l + j] = 'A' + (r % 26);
      r /= 26;
    }
    int fd = open(filename, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
      continue;
    }

    // These sanity checks should never fail. But better safe than sorry.
    struct stat sb;
    if (fstat(fd, &sb) < 0 || !S_ISREG(sb.st_mode) || sb.st_nlink != 1) {
   unexpected_file:
      NOINTR(close(fd));
      unlink(filename);
      continue;
    }

    char self[80], fullname[l + 8];
    sprintf(self, "/proc/self/fd/%d", fd);
    memset(fullname, 0, l + 8);
    if (readlink(self, fullname, l + 7) < 0) {
      if (errno != ENOENT) {
        // Fail on any error other than ENOENT, which is possible if /proc
        // has not been mounted on this system.
        goto unexpected_file;
      }
    } else if (strcmp(filename, fullname)) {
      // The actual file name does not match with the expected file name.
      // Maybe, we followed symbolic links somewhere in the path. Better not
      // use this file.
      NOINTR(close(fd));
      unlink(fullname);
      continue;
    }

    // Unlink the file so that it gets deleted when the filehandle is closed.
    unlink(filename);
    return fd;
  }

  errno = EEXIST;
  return -1;
}

void SecureMem::SetMode(SecureMem::Mode mode) {
  // This method gets called from both the trusted thread and the trusted
  // process and establishes a memory area that can be used to communicate
  // between the two.
  int fd;
  switch (mode) {
    case SANDBOX:
      NOINTR(close(fds_[1]));
      fd = Sandbox::getFd(fds_[0]);
      if (fd < 0) {
        Sandbox::die("Did not receive shared memory");
      }
      if (!(mem_ = mmap(NULL, (size_ + 4095) & ~4095, PROT_READ|PROT_EXEC,
                        MAP_SHARED, fd, 0))) {
        Sandbox::die("Could not set up shared memory region");
      }
      NOINTR(close(fds_[0]));
      break;
    case MONITOR:
      NOINTR(close(fds_[0]));
      fd = mktmpfd("/dev/shm/.sandbox");
      if (fd < 0) {
        fd = mktmpfd("/tmp/.sandbox");
      }
      if (fd < 0) {
        Sandbox::die("Cannot create temporary file in either "
                     "/dev/shm or /tmp");
      }
      if (ftruncate(fd, (size_ + 4095) & ~4095)) {
        Sandbox::die("Could not allocate shared memory");
      }
      mem_ = mmap(NULL, (size_ + 4095) & ~4095, PROT_READ|PROT_WRITE,
                  MAP_SHARED, fd, 0);
      if (!mem_) {
        Sandbox::die("Could not map shared memory");
      }
      if (!Sandbox::sendFd(fds_[1], fd)) {
        Sandbox::die("Could not share memory");
      }
      NOINTR(close(fds_[1]));
      break;
    default:
      Sandbox::die("Unexpected mode");
  }
  NOINTR(close(fd));
  fds_[0] = -1;
  fds_[1] = -1;
}

unsigned long SecureMem::receiveSystemCallInternal(int fd) {
  int err;
  if (Sandbox::read(fd, &err, sizeof(err)) != sizeof(err)) {
    Sandbox::die("Failed to receive system call");
  }
  if (err) {
    return err;
  } else {
    { char buf[80]; sprintf(buf, "Securely executing syscall %d\n", *(int *)((char *)mem_ + (__WORDSIZE == 64 ? 1 : 3))); Sandbox::write(2, buf, strlen(buf)); } // TODO(markus): remove
    return ((unsigned long (*)())mem_)();
  }
}

void SecureMem::abandonSystemCall(int fd, int err) {
  int data[2] = { -1, err };
  if (err) write(2, "System call failed\n", 19); // TODO(markus): remove
  if (Sandbox::write(fd, data, sizeof(data)) != sizeof(data)) {
    Sandbox::die("Failed to send system call");
  }
}

void SecureMem::sendSystemCallInternal(int fd, int syscall_num,
                                       void *arg1, void *arg2, void *arg3,
                                       void *arg4, void *arg5, void *arg6) {
  // There is a special-case version of this code in clone.cc. If you make
  // any changes in the code here, make sure you make the same changes in
  // clone.cc
  #if __WORDSIZE == 64
  // TODO(markus): For security reasons, we cannot use the stack. Replace the
  // RET instruction with an absolute jump.
  // TODO(markus): Check whether there is a security issue with us not being
  // able to change the shared memory page atomically. In particular, by
  // writing to threadFd(), malicious code could persuade the trusted thread
  // to run the same system call multiple times. Maybe, include a serial
  // number that has to increment sequentially?
  // TODO(markus): This code is currently not thread-safe.
  // B8 .. .. .. ..                   MOV  $..., %eax
  // 48 BF .. .. .. .. .. .. .. ..    MOV  $..., %rdi
  // 48 BE .. .. .. .. .. .. .. ..    MOV  $..., %rsi
  // 48 BA .. .. .. .. .. .. .. ..    MOV  $..., %rdx
  // 49 BA .. .. .. .. .. .. .. ..    MOV  $..., %r10
  // 49 B8 .. .. .. .. .. .. .. ..    MOV  $..., %r8
  // 49 B9 .. .. .. .. .. .. .. ..    MOV  $..., %r9
  // 0F 05                            SYSCALL
  // C3                               RET
  char *mem = reinterpret_cast<char *>(mem_);
  memcpy(mem_,
         "\xB8\x00\x00\x00\x00"
         "\x48\xBF\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x48\xBE\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x48\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xBA\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xB8\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x49\xB9\x00\x00\x00\x00\x00\x00\x00\x00"
         "\x0F\x05"
         "\xC3", 68);

  *reinterpret_cast<int   *>(mem +  1) = syscall_num;
  *reinterpret_cast<void **>(mem +  7) = arg1;
  *reinterpret_cast<void **>(mem + 17) = arg2;
  *reinterpret_cast<void **>(mem + 27) = arg3;
  *reinterpret_cast<void **>(mem + 37) = arg4;
  *reinterpret_cast<void **>(mem + 47) = arg5;
  *reinterpret_cast<void **>(mem + 57) = arg6;
  #else
  // 55                               PUSH %ebp
  // 53                               PUSH %ebx
  // B8 .. .. .. ..                   MOV  $..., %eax
  // BB .. .. .. ..                   MOV  $..., %ebx
  // B9 .. .. .. ..                   MOV  $..., %ecx
  // BA .. .. .. ..                   MOV  $..., %edx
  // BE .. .. .. ..                   MOV  $..., %esi
  // BF .. .. .. ..                   MOV  $..., %edi
  // BD .. .. .. ..                   MOV  $..., %ebp
  // CD 80                            INT  $0x80
  // 5B                               POP  %ebx
  // 5D                               POP  %ebp
  // C3                               RET
  char *mem = reinterpret_cast<char *>(mem_);
  memcpy(mem_,
         "\x55"
         "\x53"
         "\xB8\x00\x00\x00\x00"
         "\xBB\x00\x00\x00\x00"
         "\xB9\x00\x00\x00\x00"
         "\xBA\x00\x00\x00\x00"
         "\xBE\x00\x00\x00\x00"
         "\xBF\x00\x00\x00\x00"
         "\xBD\x00\x00\x00\x00"
         "\xCD\x80"
         "\x5B"
         "\x5D"
         "\xC3", 42);
  *reinterpret_cast<int   *>(mem +  3) = syscall_num;
  *reinterpret_cast<void **>(mem +  8) = arg1;
  *reinterpret_cast<void **>(mem + 13) = arg2;
  *reinterpret_cast<void **>(mem + 18) = arg3;
  *reinterpret_cast<void **>(mem + 23) = arg4;
  *reinterpret_cast<void **>(mem + 28) = arg5;
  *reinterpret_cast<void **>(mem + 33) = arg6;
  #endif
  abandonSystemCall(fd, 0);
}

} // namespace
