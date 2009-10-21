#include "sandbox_impl.h"
#include <dirent.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

// #define THREADS 1000
// #define ITER    100

#define THREADS 2
#define ITER    2

static long long tsc() {
  long long rc;
  asm volatile(
      "rdtsc\n"
      "mov %%eax, (%0)\n"
      "mov %%edx, 4(%0)\n"
      :
      : "c"(&rc), "a"(-1), "d"(-1));
  return rc;
}

static void *empty(void *arg) {
  return mmap(0, 4096, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
}

static void *fnc(void *arg) {
  struct timeval tv;
  if (gettimeofday(&tv, 0)) {
    printf("In thread:\ngettimeofday() failed\n");
  } else {
    printf("In thread: usec: %ld\n", (long)tv.tv_usec);
  }
  printf("In thread: TSC: %llx\n", tsc());
  for (int i = 0; i < ITER; i++) {
    pthread_t t;
    if (!pthread_create(&t, NULL, empty, NULL)) {
      pthread_join(t, NULL);
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
//{ char buf[128]; sprintf(buf, "cat /proc/%d/maps", getpid()); system(buf); }
  StartSeccompSandbox();
  write(2, "In secure mode, now!\n", 21);

  printf("TSC: %llx\n", tsc());
  printf("TSC: %llx\n", tsc());

  #if defined(__x86_64__)
  asm volatile("mov $2, %%edi\n"
               "lea 100f, %%rsi\n"
               "mov $101f-100f, %%edx\n"
               "mov $1, %%eax\n"
               "int $0\n"
               "jmp 101f\n"
          "100:.ascii \"Hello world (INT $0 worked)\\n\"\n"
          "101:\n"
               :
               :
               : "rax", "rdi", "rsi", "rdx");
  #elif defined(__i386__)
  asm volatile("mov $2, %%ebx\n"
               "lea 100f, %%ecx\n"
               "mov $101f-100f, %%edx\n"
               "mov $4, %%eax\n"
               "int $0\n"
               "jmp 101f\n"
          "100:.ascii \"Hello world (INT $0 worked)\\n\"\n"
          "101:\n"
               :
               :
               : "eax", "ebx", "ecx", "edx");
  #endif

  int pair[2];
  socketpair(AF_UNIX, SOCK_STREAM, 0, pair);

  printf("uid: %d\n", getuid());
  dlopen("libncurses.so.5", RTLD_LAZY);

  struct timeval tv;
  if (gettimeofday(&tv, 0)) {
    printf("gettimeofday() failed\n");
  } else {
    printf("usec: %ld\n", (long)tv.tv_usec);
  }
  fflush(stdout);
  fopen("/usr/share/doc", "r");
  fopen("/usr/share/doc", "r");
  isatty(0);
  for (int i = 0; i < THREADS; ++i) {
    pthread_t t;
    pthread_create(&t, NULL, fnc, NULL);
  }
  for (int i = 0; i < 10; i++) {
    mmap(0, 4096, PROT_NONE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  }
  printf("Hello %s\n", "world");
  if (gettimeofday(&tv, 0)) {
    printf("gettimeofday() failed\n");
  } else {
    printf("usec: %ld\n", (long)tv.tv_usec);
  }
  struct stat sb;
  stat("/", &sb);
  DIR *dirp = opendir("/");
  if (dirp) {
    readdir(dirp);
    closedir(dirp);
  }

  puts("Done");
  exit(0);
  return 0;
}
