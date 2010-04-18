// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "linux_syscall_support.h"

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

#ifdef THREADS
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
#endif

int main(int argc, char *argv[]) {
//{ char buf[128]; sprintf(buf, "cat /proc/%d/maps", getpid()); system(buf); }
  struct timeval tv, tv0;
  gettimeofday(&tv0, 0);
  if (SupportsSeccompSandbox(-1)) {
    puts("Sandbox is supported. Enabling it now...");
  } else {
    puts("There is insufficient support for the seccomp sandbox. Exiting...");
    return 1;
  }
  gettimeofday(&tv, 0);
  printf("It takes %fms to start the sandbox\n",
         tv.tv_sec  * 1000.0 + tv.tv_usec  / 1000.0 -
         tv0.tv_sec * 1000.0 - tv0.tv_usec / 1000.0);

  sigset_t orig_sigmask = { { 0 } };
  sigemptyset(&orig_sigmask);
  sigprocmask(-1, NULL, &orig_sigmask);

  StartSeccompSandbox();
  write(2, "In secure mode, now!\n", 21);

  sigset_t sigmask = { { 0 } }, old_sigmask = { { 0 } };
  sigemptyset(&sigmask);
  sigemptyset(&old_sigmask);
  sigaddset(&sigmask, SIGALRM);
  sigprocmask(SIG_SETMASK, &sigmask, &old_sigmask);
  printf("Original signal mask: 0x%llX, old mask: 0x%llX, new mask: 0x%llX, ",
         *(unsigned long long *)&orig_sigmask,
         *(unsigned long long *)&old_sigmask,
         *(unsigned long long *)&sigmask);
  sigprocmask(SIG_SETMASK, &old_sigmask, &old_sigmask);
  printf("cur mask: 0x%llX, restored mask: 0x%llX\n",
         *(unsigned long long *)&old_sigmask,
         *(unsigned long long *)&orig_sigmask);

  gettimeofday(&tv, 0);
  gettimeofday(&tv, 0);
  gettimeofday(&tv, 0);
  gettimeofday(&tv, 0);
  printf("TSC: %llx\n", tsc());
  printf("TSC: %llx\n", tsc());

  #if defined(__x86_64__)
  asm volatile("mov $2, %%edi\n"
               "lea 100f(%%rip), %%rsi\n"
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

  if (gettimeofday(&tv, 0)) {
    printf("gettimeofday() failed\n");
  } else {
    printf("usec: %ld\n", (long)tv.tv_usec);
  }
  fflush(stdout);
  fopen("/usr/share/doc", "r");
  fopen("/usr/share/doc", "r");
  isatty(0);
#ifdef THREADS
  pthread_t threads[THREADS];
  for (int i = 0; i < THREADS; ++i) {
    pthread_create(&threads[i], NULL, fnc, NULL);
  }
#endif
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
#ifdef THREADS
  for (int i = 0; i < THREADS; ++i) {
    pthread_join(threads[i], NULL);
  }
  pthread_create(&threads[0], NULL, fnc, NULL);
  pthread_join(threads[0], NULL);
#endif

  puts("Done");
  exit(0);
  return 0;
}
