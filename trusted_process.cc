#include <map>

#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

struct Thread {
  int   fd;
  char* mem;
};

void Sandbox::initializeProtectedMap(int fd) {
  // Read the memory mappings as they were before the sandbox takes effect.
  // These mappings cannot be changed by the sandboxed process.
  {
    int mapsFd;
    if (!getFd(fd, &mapsFd)) {
   maps_failure:
      die("Cannot access /proc/self/maps");
    }
    char line[80];
    FILE *fp = fdopen(mapsFd, "r");
    for (bool truncated = false;;) {
      if (fgets(line, sizeof(line), fp) == NULL) {
        if (feof(fp) || errno != EINTR) {
          break;
        }
        continue;
      }
      if (!truncated) {
        unsigned long start, stop;
        char *ptr = line;
        errno = 0;
        start = strtoul(ptr, &ptr, 16);
        if (errno || *ptr++ != '-') {
       parse_failure:
          die("Failed to parse /proc/self/maps");
        }
        stop = strtoul(ptr, &ptr, 16);
        if (errno || *ptr++ != ' ') {
          goto parse_failure;
        }
        protectedMap_[reinterpret_cast<void *>(start)] = stop - start;
      }
      truncated = strchr(line, '\n') == NULL;
    }
    SysCalls sys;
    NOINTR_SYS(sys.close(mapsFd));
    if (write(sys, fd, &mapsFd, sizeof(mapsFd)) != sizeof(mapsFd)) {
      goto maps_failure;
    }
  }
}

void Sandbox::trustedProcess(void *args_) {
  // Set up securely shared memory for main thread
  static std::map<pid_t, struct Thread> threads;
  ChildArgs* args     = reinterpret_cast<ChildArgs *>(args_);
  initializeProtectedMap(args->fd2);

  Thread* main_thread = &threads[args->tid];
  main_thread->fd     = args->fd0;
  main_thread->mem    = args->mem;
  mprotect(args->mem, 4096, PROT_READ | PROT_WRITE);

  // Dispatch system calls that have been forwarded from the trusted thread(s).
  SysCalls sys;
  for (;;) {
    struct {
      unsigned int sysnum;
      pid_t        tid;
    } __attribute__((packed)) header;
    int rc;
    if ((rc = read(sys, args->fd2, &header, sizeof(header))) !=sizeof(header)){
      if (rc) {
        die("Failed to read system call number and thread id");
      }
      die();
    }
    std::map<pid_t, struct Thread>::const_iterator iter =
                                                      threads.find(header.tid);
    if (iter == threads.end()) {
      die("Received request from unknown thread");
    }
    if (header.sysnum > maxSyscall ||
        !syscallTable[header.sysnum].trustedProcess) {
      die("Trusted process encountered unexpected system call");
    }
    syscallTable[header.sysnum].trustedProcess(args->fd1,
                                               args->fd2,
                                               iter->second.fd,
                                               args->fd3,
                                               iter->second.mem);
  }
}

} // namespace
