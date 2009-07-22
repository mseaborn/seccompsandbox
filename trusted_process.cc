#include <dirent.h>
#include <map>

#include "sandbox_impl.h"
#include "syscall_table.h"

namespace playground {

struct Thread {
  int              fdPub, fd;
  SecureMem::Args* mem;
  char*            lastVerifiedString;
  int              lastVerifiedStringLen;
};
static struct Thread* currentThread;

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
  if (!secureMemPool_.empty()) {
    void* rc = secureMemPool_.back();
    secureMemPool_.pop_back();
    return rc;
  }
  return NULL;
}

char* Sandbox::getSecureStringBuffer(int length) {
  // We have to make sure that in two consecutive calls that we send to the
  // trusted thread, we don't pass the same address for the verified string
  // (typically used for filenames). Otherwise, an attacker could manipulate
  // the global futex and time a request for the trusted process just right
  // so that it changes the string before the trusted thread had a chance to
  // retrieve it.
  if (length < 0) {
    return NULL;
  }

  // Allow for trailing zero byte
  length++;
  if (currentThread->lastVerifiedString) {
    memset(currentThread->lastVerifiedString, 0,
           currentThread->lastVerifiedStringLen);
  }
  char *rc                               = NULL;
  if (!currentThread->lastVerifiedString ||
      currentThread->lastVerifiedString - currentThread->mem->pathname >=
      length) {
    rc                                   = currentThread->mem->pathname;
  } else {
    char *nextAvailable                  =
      currentThread->lastVerifiedString + currentThread->lastVerifiedStringLen;
    if (currentThread->mem->pathname + sizeof(currentThread->mem->pathname) -
        length >= nextAvailable) {
      rc                                 = nextAvailable;
    }
  }
  if (rc) {
    memset(rc, 0, length);
    currentThread->lastVerifiedStringLen = length;
    currentThread->lastVerifiedString    = rc;
  }
  return rc;
}

void Sandbox::trustedProcess(int parentProc, int processFdPub, int sandboxFd,
                             int cloneFd, void* secureArena) {
  std::map<long long, struct Thread> threads;
  SysCalls  sys;
  long long cookie        = 0;

  // The very first entry in the secure memory arena has been assigned to the
  // initial thread. The remaining entries are available for allocation.
  void* startAddress      = secureArena;
  for (int i = 0; i < kMaxThreads-1; i++) {
    startAddress          = reinterpret_cast<char *>(startAddress) + 8192;
    secureMemPool_.push_back(startAddress);
  }

newThreadCreated:
  Thread *newThread       = &threads[++cookie];
  memset(newThread, 0, sizeof(Thread));

  int shmFd;
  SecureMem::Args* newMem = reinterpret_cast<SecureMem::Args*>(
                                                     makeSharedMemory(&shmFd));
  newThread->mem          = newMem;
  newMem->cookie          = cookie;
  struct {
    SecureMem::Args* self;
    int              tid;
    int              fdPub;
  } __attribute__((packed)) data;
  ssize_t dataLen         = sizeof(data);
  if (!getFd(cloneFd, &newThread->fdPub, &newThread->fd, &data, &dataLen) ||
      dataLen != sizeof(data)) {
    // We get here either because the sandbox got corrupted, or because our
    // parent process has terminated.
    if (newThread->fdPub || dataLen) {
      die("Failed to receive new thread information");
    }
    die();
  }
  newMem->self            = data.self;
  newMem->threadId        = data.tid;
  newMem->threadFdPub     = data.fdPub;
  sendFd(newThread->fdPub, shmFd, -1, NULL, 0);
  NOINTR_SYS(sys.close(shmFd));

  // TODO(markus): remove
  /***/printf("Adding new thread %lld, shm=%p, fdPub=%d, fd=%d\n",
  /***/       cookie, newThread->mem->self, newThread->fdPub, newThread->fd);

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
    currentThread         = &iter->second;
    if (header.sysnum > maxSyscall ||
        !syscallTable[header.sysnum].trustedProcess) {
      die("Trusted process encountered unexpected system call");
    }
    if (syscallTable[header.sysnum].trustedProcess(parentProc,
                                                   sandboxFd,
                                                   currentThread->fdPub,
                                                   currentThread->fd,
                                                   currentThread->mem) &&
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

void* Sandbox::createTrustedProcess(int processFdPub, int sandboxFd,
                                    int cloneFdPub, int cloneFd) {
  // Allocate memory that will be used for storing the secure memory. While
  // we allow this memory area to be empty at times (e.g. when not all threads
  // are in use), we make sure that it never gets any user-allocated memory.
  char *secureArena = reinterpret_cast<char *>(
      mmap(reinterpret_cast<void *>(4096), 8192*kMaxThreads, PROT_NONE,
           MAP_PRIVATE|MAP_ANONYMOUS, -1, 0));
  if (secureArena == MAP_FAILED) {
    die("Failed to allocate secure memory arena");
  }

  int parentProc    = open("/proc/self/", O_RDONLY|O_DIRECTORY);
  if (parentProc < 0) {
    die("Failed to access /proc/self");
  }

  // Create a trusted process that can evaluate system call parameters and
  // decide whether a system call should execute. This process runs outside of
  // the seccomp sandbox. It communicates with the sandbox'd process through
  // a socketpair() and through securely shared memory.
  pid_t pid         = fork();
  if (pid < 0) {
    die("Failed to create trusted process");
  }
  if (!pid) {
    // Close all file handles except for sandboxFd, cloneFd, and stdio
    DIR *dir        = opendir("/proc/self/fd");
    if (dir == 0) {
      // If we don't know the list of our open file handles, just try closing
      // all valid ones.
      for (int fd = sysconf(_SC_OPEN_MAX); --fd > 2; ) {
        if (fd != parentProc && fd != sandboxFd && fd != cloneFd) {
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
        int fd      = atoi(res->d_name);
        if (fd > 2 &&
            fd != parentProc && fd != sandboxFd && fd != cloneFd &&
            fd != dirfd(dir)) {
          close(fd);
        }
      }
      closedir(dir);
    }

    initializeProtectedMap(sandboxFd);
    trustedProcess(parentProc, processFdPub, sandboxFd, cloneFd, secureArena);
    die();
  }
  close(parentProc);
  close(sandboxFd);
  return secureArena;
}

} // namespace
