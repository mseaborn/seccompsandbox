#include <dirent.h>
#include <map>

#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

struct Thread {
  int              fdPub, fd;
  SecureMem::Args* mem;
};

void* Sandbox::makeSharedMemory(int* fd) {
  // If /dev/shm does not exist, fall back on /tmp
  SysCalls::kernel_stat sb;
  SysCalls sys;
  char fn[24];
  if (sys.stat("/dev/shm/", &sb) || !S_ISDIR(sb.st_mode)) {
    strcpy(fn, "/tmp/.sandboxXXXXXX");
  } else {
    strcpy(fn, "/dev/shm/.sandboxXXXXXX");
  }

  for (;;) {
    // Replace the last six characters with a randomized string
    char* ptr  = strrchr(fn, '\000');
    struct timeval tv;
    sys.gettimeofday(&tv, NULL);
    unsigned r = 16807*(((unsigned long long)tv.tv_usec << 16) ^ tv.tv_sec);
    for (int j = 0; j < 6; j++) {
      *--ptr   = 'A' + (r % 26);
      r       *= 16807;
    }

    *fd        = sys.open(fn, O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW,0600);
    if (*fd < 0) {
      continue;
    }

    if (sys.unlink(fn)) {
   shmFailure:
      die("Fatal error setting up shared memory");
    }
    NOINTR_SYS(sys.ftruncate(*fd, 4096));

    void* page = sys.MMAP(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED,*fd, 0);
    if (page == MAP_FAILED) {
      goto shmFailure;
    }
    return page;
  }
}

void* Sandbox::getSecureMem() {
  return NULL;
}

void Sandbox::trustedProcess(int processFdPub, int sandboxFd,
                             void* secureArena) {
  std::map<long long, struct Thread> threads;
  SysCalls  sys;
  long long cookie       = 0;

newThreadCreated:
  Thread *newThread      = &threads[++cookie];

  int shmFd;
  newThread->mem         = reinterpret_cast<SecureMem::Args*>(
                                                     makeSharedMemory(&shmFd));
  newThread->mem->cookie = cookie;
  ssize_t selfLen        = sizeof(newThread->mem->self);
  if (!getFd(sandboxFd, &newThread->fdPub, &newThread->fd,
             &newThread->mem->self, &selfLen) ||
      selfLen != sizeof(newThread->mem->self) ||
      !sendFd(newThread->fdPub, shmFd, -1, NULL, 0)) {
    die("Failed to receive new thread information");
  }
  NOINTR_SYS(sys.close(shmFd));

  // TODO(markus): remove
  /***/printf("Adding new thread %lld, shm=%p, fdPub=%d, fd=%d\n",
  /***/       cookie, newThread->mem, newThread->fdPub, newThread->fd);

  // Dispatch system calls that have been forwarded from the trusted thread(s).
  for (;;) {
    struct {
      unsigned int sysnum;
      long long    cookie;
    } __attribute__((packed)) header;
    int rc;
    if ((rc = read(sys, sandboxFd, &header, sizeof(header))) !=sizeof(header)){
      if (rc) {
        die("Failed to read system call number and thread id");
      }
      die();
    }
    std::map<long long, struct Thread>::iterator iter =
                                                   threads.find(header.cookie);
    if (iter == threads.end()) {
      die("Received request from unknown thread");
    }
    if (header.sysnum > maxSyscall ||
        !syscallTable[header.sysnum].trustedProcess) {
      die("Trusted process encountered unexpected system call");
    }
    if (syscallTable[header.sysnum].trustedProcess(sandboxFd,
                                                   iter->second.fdPub,
                                                   iter->second.fd,
                                                   iter->second.mem) &&
        header.sysnum == __NR_clone) {
      goto newThreadCreated;
    } else if (header.sysnum == __NR_exit) {
      NOINTR_SYS(sys.close(iter->second.fdPub));
      NOINTR_SYS(sys.close(iter->second.fd));
      threads.erase(iter);
    }
  }
}

void Sandbox::initializeProtectedMap(int fd) {
  int mapsFd, shmFd;
  if (!getFd(fd, &mapsFd, &shmFd, NULL, NULL)) {
 maps_failure:
    die("Cannot access /proc/self/maps");
  }

  // Set up a shared memory page that will be used to hold our syscall_mutex_
  SysCalls sys;
  void* page = sys.MMAP(NULL, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, shmFd,0);
  if (page == MAP_FAILED) {
    die("Cannot create shared memory");
  }
  syscall_mutex_ = reinterpret_cast<mutex_t*>(page);
  NOINTR_SYS(sys.close(shmFd));

  // Read the memory mappings as they were before the sandbox takes effect.
  // These mappings cannot be changed by the sandboxed process.
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
  NOINTR_SYS(sys.close(mapsFd));

  // Prevent low address memory allocations. Some buggy kernels allow those
  if (protectedMap_[0] < (64 << 10)) {
    protectedMap_[0] = 64 << 10;
  }

  // Let the sandbox know that we are done parsing the memory map.
  if (write(sys, fd, &mapsFd, sizeof(mapsFd)) != sizeof(mapsFd)) {
    goto maps_failure;
  }
}

void* Sandbox::createTrustedProcess(int processFdPub, int sandboxFd) {
  // Create a trusted process that can evaluate system call parameters and
  // decide whether a system call should execute. This process runs outside of
  // the seccomp sandbox. It communicates with the sandbox'd process through
  // a socketpair() and through securely shared memory.
  SysCalls sys;

  // Allocate memory that will be used for storing the secure memory. While
  // we allow this memory area to be empty at times (e.g. when not all threads
  // are in use), we make sure that it never gets any user-allocated memory.
  char *secureArena = reinterpret_cast<char *>(
      sys.MMAP(reinterpret_cast<void *>(4096), 8192*kMaxThreads, PROT_NONE,
               MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));
  if (secureArena == MAP_FAILED) {
    die("Failed to allocate secure memory arena");
  }

  pid_t pid       = fork();
  if (pid < 0) {
    die("Failed to create trusted process");
  }
  if (!pid) {
    // Close all file handles except for sandboxFd, cloneFd, and stdio
    DIR *dir      = opendir("/proc/self/fd");
    if (dir == 0) {
      // If we don't know the list of our open file handles, just try closing
      // all valid ones.
      for (int fd = sysconf(_SC_OPEN_MAX); --fd > 2; ) {
        if (fd != sandboxFd) {
          close(fd);
        }
      }
    } else {
      // If available, if is much more efficient to just close the file
      // handles that show up in /proc/self/fd/
      struct dirent de, *res;
      while (!readdir_r(dir, &de, &res) && res) {
        if (res->d_name[0] < '0')
          continue;
        int fd  = atoi(res->d_name);
        if (fd > 2 && fd != sandboxFd && fd != dirfd(dir)) {
          close(fd);
        }
      }
      closedir(dir);
    }

    initializeProtectedMap(sandboxFd);
    trustedProcess(processFdPub, sandboxFd, secureArena);
    die();
  }
  close(sandboxFd);
  return secureArena;
}

} // namespace
