#include "sandbox_impl.h"
#include <dirent.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define THREADS 10
#define ITER    10000

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
  for (int i = 0; i < ITER; i++) {
    pthread_t t;
    if (!pthread_create(&t, NULL, empty, NULL)) {
      pthread_join(t, NULL);
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  startSandbox();
  write(2, "In secure mode, now!\n", 21);

  struct timeval tv;
  if (gettimeofday(&tv, 0)) {
    printf("gettimeofday() failed\n");
  } else {
    printf("usec: %ld\n", (long)tv.tv_usec);
  }
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
  return 0;
}
