#include "sandbox_impl.h"
#include <dirent.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

static void *fnc(void *arg) {
  struct timeval tv;
  if (gettimeofday(&tv, 0)) {
    printf("In thread:\ngettimeofday() failed\n");
  } else {
    printf("In thread: usec: %ld\n", (long)tv.tv_usec);
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
  pthread_t t;
  pthread_create(&t, NULL, fnc, NULL);
  pthread_join(t, NULL);
  printf("Hello %s\n", "world");
  if (gettimeofday(&tv, 0)) {
    printf("gettimeofday() failed\n");
  } else {
    printf("usec: %ld\n", (long)tv.tv_usec);
  }
  struct stat sb;
  stat("/", &sb);
  DIR *dirp = opendir("/");
  readdir(dirp);
  closedir(dirp);

  puts("Done");
  return 0;
}
