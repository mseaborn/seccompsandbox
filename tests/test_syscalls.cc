// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <asm/unistd.h>
#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <pty.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

// This header file should be included before "sandbox_impl.h" for
// SYS_SYSCALL_ENTRYPOINT to take effect.
#define SYS_SYSCALL_ENTRYPOINT "playground$syscallEntryPoint"
#include "linux_syscall_support.h"

#include "debug.h"
#include "sandbox_impl.h"

#ifdef DEBUG
#define MSG(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define MSG(fmt, ...) do { } while (0)
#endif

// Checks that "expr" evaluates to "true". Returns value of "expr".
#define CHECK(expr)                                                           \
  ({ typeof (expr) check_res = (expr);                                        \
     if (!check_res) {                                                        \
       fprintf(stderr, "%s:%d: Check failed in \"%s\": %s\n",                 \
               __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr);               \
       _exit(1);                                                              \
     }                                                                        \
     check_res;                                                               \
  })

// Checks that "expr" evaluates to "true". Prints "errno" value on failure.
// Returns value of "expr".
#define CHECK_SUCCEEDS(expr)                                                  \
  ({ typeof (expr) check_res = (expr);                                        \
     if (!check_res) {                                                        \
       char errmsg[80];                                                       \
       fprintf(stderr, "%s:%d: Check failed in \"%s\": %s: \"%s\"\n",         \
               __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr,                \
               strerror_r(errno, errmsg, sizeof(errmsg)));                    \
       _exit(1);                                                              \
     }                                                                        \
     check_res;                                                               \
  })

// Checks that "expr" evaluates to "true", or that is sets "errno" to
// "exp_errno". Prints "errno" value on failure. Returns value of "expr".
#define CHECK_MAYFAIL(expr, exp_errno)                                        \
  ({ typeof (expr) check_res = (expr);                                        \
    if (!check_res && errno != (exp_errno)) {                                 \
      char errmsg1[80], errmsg2[80];                                          \
      fprintf(stderr, "%s:%d: Check failed in \"%s\": %s: expected \"%s\" "   \
              "but was \"%s\"\n",                                             \
              __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr,                 \
              strerror_r(exp_errno, errmsg1, sizeof(errmsg1)),                \
              strerror_r(errno, errmsg2, sizeof(errmsg2)));                   \
      _exit(1);                                                               \
    }                                                                         \
    check_res;                                                                \
  })

// Checks that "expr" evaluates to "-1" and that it sets "errno" to
// "exp_errno". Prints actual "errno" value otherwise. Returns value of "expr".
#define CHECK_ERRNO(expr, exp_errno)                                          \
  ({ typeof (expr) check_res = (expr);                                        \
    if (check_res != (typeof check_res)-1) {                                  \
       fprintf(stderr, "%s:%d: Check unexpectedly succeeded in \"%s\": %s\n", \
               __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr);               \
       _exit(1);                                                              \
    } else if (errno != (exp_errno)) {                                        \
      char errmsg1[80], errmsg2[80];                                          \
      fprintf(stderr, "%s:%d: Check failed in \"%s\": %s: expected \"%s\" "   \
              "but was \"%s\"\n",                                             \
              __FILE__, __LINE__, __PRETTY_FUNCTION__, #expr,                 \
              strerror_r(exp_errno, errmsg1, sizeof(errmsg1)),                \
              strerror_r(errno, errmsg2, sizeof(errmsg2)));                   \
      _exit(1);                                                               \
    }                                                                         \
    check_res;                                                                \
  })

int g_intended_status_fd = -1;

// Declares the wait() status that the test subprocess intends to exit with.
void intend_exit_status(int val, bool is_signal) {
  if (is_signal) {
    val = W_EXITCODE(0, val);
  } else {
    val = W_EXITCODE(val, 0);
  }
  if (g_intended_status_fd != -1) {
    CHECK_SUCCEEDS(write(g_intended_status_fd, &val, sizeof(val)) ==
                   sizeof(val));
  } else {
    // This prints in cases where we run one test without forking
    printf("Intending to exit with status %i...\n", val);
  }
}


// This is basically a marker to grep for.
#define TEST(name) void name()

TEST(test_dup) {
  StartSeccompSandbox();
  // Test a simple syscall that is marked as UNRESTRICTED_SYSCALL.
  int fd;
  CHECK_SUCCEEDS((fd = dup(1)) >= 0);
  CHECK_SUCCEEDS(close(fd) == 0);
}

TEST(test_segfault) {
  StartSeccompSandbox();
  // Check that the sandbox's SIGSEGV handler does not stop the
  // process from dying cleanly in the event of a real segfault.
  intend_exit_status(SIGSEGV, true);
  asm("hlt");
}

TEST(test_exit) {
  StartSeccompSandbox();
  intend_exit_status(123, false);
  _exit(123);
}

// Although test_thread and test_clone test __NR_exit, they do not
// necessarily let the trusted thread's __NR_exit handler run to
// completion, because the first thread can call __NR_exit_group
// before that happens.  So we test __NR_exit on its own.
TEST(test_thread_exit) {
  StartSeccompSandbox();
  // The trusted thread and untrusted thread will be racing to return
  // the exit status, which is fixed as 1 for the untrusted thread.
  intend_exit_status(1, false);
  syscall(__NR_exit, 1);
}

// This has an off-by-three error because it counts ".", "..", and the
// FD for the /proc/self/fd directory.  This doesn't matter because it
// is only used to check for differences in the number of open FDs.
static int count_fds() {
  DIR *dir;
  CHECK_SUCCEEDS((dir = opendir("/proc/self/fd")) != NULL);
  int count = 0;
  while (1) {
    struct dirent *d = readdir(dir);
    if (d == NULL)
      break;
    count++;
  }
  CHECK_SUCCEEDS(closedir(dir) == 0);
  return count;
}

static void *thread_func(void *x) {
  int *ptr = (int *) x;
  *ptr = 123;
  MSG("In new thread\n");
  return (void *) 456;
}

TEST(test_thread) {
  playground::g_policy.allow_file_namespace = true;  // To allow count_fds()
  StartSeccompSandbox();
  int fd_count1 = count_fds();
  pthread_t tid;
  int x = 999;
  void *result;
  pthread_create(&tid, NULL, thread_func, &x);
  MSG("Waiting for thread\n");
  pthread_join(tid, &result);
  CHECK(result == (void *) 456);
  CHECK(x == 123);
  // Check that the process has not leaked FDs.
  int fd_count2 = count_fds();
  CHECK(fd_count2 == fd_count1);
}

static int clone_func(void *x) {
  int *ptr = (int *) x;
  *ptr = 124;
  MSG("In thread\n");
  // On x86-64, returning from this function calls the __NR_exit_group
  // syscall instead of __NR_exit.
  syscall(__NR_exit, 100);
  // Not reached.
  return 200;
}

#if defined(__i386__)
static int get_gs() {
  int gs;
  asm volatile("mov %%gs, %0" : "=r"(gs));
  return gs;
}
#endif

static void *get_tls_base() {
  void *base;
#if defined(__x86_64__)
  asm volatile("mov %%fs:0, %0" : "=r"(base));
#elif defined(__i386__)
  asm volatile("mov %%gs:0, %0" : "=r"(base));
#else
#error Unsupported target platform
#endif
  return base;
}

// The sandbox requires us to pass CLONE_TLS to clone().  Pass
// settings that are enough to copy the parent thread's TLS setup.
// This allows us to invoke libc in the child thread.
class CopyTLSInfo {
public:
#if defined(__x86_64__)
  void *get_clone_tls_arg() {
    return get_tls_base();
  }
#elif defined(__i386__)
  struct user_desc tls_desc;
  void *get_clone_tls_arg() {
    tls_desc.entry_number = get_gs() >> 3;
    tls_desc.base_addr = (long) get_tls_base();
    tls_desc.limit = 0xfffff;
    tls_desc.seg_32bit = 1;
    tls_desc.contents = 0;
    tls_desc.read_exec_only = 0;
    tls_desc.limit_in_pages = 1;
    tls_desc.seg_not_present = 0;
    tls_desc.useable = 1;
    return &tls_desc;
  }
#else
#error Unsupported target platform
#endif
};

void wait_for_child_thread(int *tid_ptr, int tid) {
  while (*tid_ptr == tid) {
    CHECK_MAYFAIL(syscall(__NR_futex, tid_ptr, FUTEX_WAIT, tid, NULL) == 0,
                  EAGAIN);
  }
  CHECK(*tid_ptr == 0);
}

TEST(test_clone) {
  playground::g_policy.allow_file_namespace = true;  // To allow count_fds()
  StartSeccompSandbox();
  int fd_count1 = count_fds();
  int stack_size = 0x1000;
  char *stack;
  CHECK_SUCCEEDS((stack = (char *) malloc(stack_size)) != NULL);
  int flags = CLONE_VM | CLONE_FS | CLONE_FILES |
    CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM |
    CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
  int tid = -1;
  int x = 999;
  CopyTLSInfo tls_info;
  int rc;
  CHECK_SUCCEEDS((rc = clone(clone_func, (void *) (stack + stack_size),
                             flags, &x, &tid, tls_info.get_clone_tls_arg(),
                             &tid)) > 0);
  wait_for_child_thread(&tid, rc);
  CHECK(x == 124);
  // Check that the process has not leaked FDs.
  int fd_count2 = count_fds();
  CHECK(fd_count2 == fd_count1);
}

#if defined(__x86_64)
const int NO_REGISTERS = 15;
const long TEST_VALUE = 0x4321000012340000;
const int SYSCALL_ARG_REGS[] = {
  0, // %rax
  5, // %rdi
  4, // %rsi
  3, // %rdx
  9, // %r10
  7, // %r8
  8, // %r9
};
#elif defined(__i386__)
const int NO_REGISTERS = 7;
const long TEST_VALUE = 0x12340000;
const int SYSCALL_ARG_REGS[] = {
  0, // %eax
  1, // %ebx
  2, // %ecx
  3, // %edx
  4, // %esi
  5, // %edi
  6, // %ebp
};
#else
#error Unsupported target platform
#endif

long g_input_regs[NO_REGISTERS];
long g_out_regs_parent[NO_REGISTERS];
long g_out_regs_child[NO_REGISTERS];
extern "C" int clone_test_helper();

// Test that clone() preserves all the registers it should do in the
// parent and child threads.  This is a hassle to test, because it
// requires a helper (written in assembly) for setting up and saving
// registers.  glibc does not care about most registers being
// preserved in the child thread, which means register preservation is
// not otherwise tested, but glibc *could* depend on it in the future.
TEST(test_clone_preserves_registers) {
  StartSeccompSandbox();
  int stack_size = 0x1000;
  char *stack;
  CHECK_SUCCEEDS((stack = (char *) malloc(stack_size)) != NULL);
  int flags = CLONE_VM | CLONE_FS | CLONE_FILES |
    CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM |
    CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
  int tid = -1;
  CopyTLSInfo tls_info;
  for (int i = 0; i < NO_REGISTERS; i++) {
    // Fill out an arbitrary value that we can test for later.
    g_input_regs[i] = TEST_VALUE + i;
  }
  g_input_regs[SYSCALL_ARG_REGS[0]] = __NR_clone;
  g_input_regs[SYSCALL_ARG_REGS[1]] = flags;
  g_input_regs[SYSCALL_ARG_REGS[2]] = (long) (stack + stack_size);
  g_input_regs[SYSCALL_ARG_REGS[3]] = (long) &tid;
#if defined(__x86_64__)
  g_input_regs[SYSCALL_ARG_REGS[4]] = (long) &tid;
  g_input_regs[SYSCALL_ARG_REGS[5]] = (long) tls_info.get_clone_tls_arg();
#elif defined(__i386__)
  g_input_regs[SYSCALL_ARG_REGS[4]] = (long) tls_info.get_clone_tls_arg();
  g_input_regs[SYSCALL_ARG_REGS[5]] = (long) &tid;
#else
#error Unsupported target platform
#endif
  int rc;
  CHECK((rc = clone_test_helper()) > 0);
  wait_for_child_thread(&tid, rc);
  bool success = true;
  for (int regnum = 0; regnum < NO_REGISTERS; regnum++) {
#if defined(__x86_64__) || defined(__i386__)
    // The result register, %eax/%rax, is always overwritten.
    if (regnum == 0)
      continue;
#endif
#if defined(__x86_64__)
    // %r11 can be overwritten by a system call.
    if (regnum == 10)
      continue;
#endif
    if (g_out_regs_parent[regnum] != g_input_regs[regnum] ||
        g_out_regs_child[regnum] != g_input_regs[regnum]) {
      printf("mismatch in register %i: %lx %lx %lx\n",
             regnum, g_input_regs[regnum], g_out_regs_parent[regnum],
             g_out_regs_child[regnum]);
      success = false;
    }
  }
  CHECK(success);
}

static int uncalled_clone_func(void *x) {
  printf("In thread func, which shouldn't happen\n");
  return 1;
}

TEST(test_clone_disallowed_flags) {
  StartSeccompSandbox();
  int stack_size = 4096;
  char *stack;
  CHECK_SUCCEEDS((stack = (char *) malloc(stack_size)) != NULL);
  /* We omit the flags CLONE_SETTLS, CLONE_PARENT_SETTID and
     CLONE_CHILD_CLEARTID, which is disallowed by the sandbox. */
  int flags = CLONE_VM | CLONE_FS | CLONE_FILES |
    CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM;
  CHECK_ERRNO(clone(uncalled_clone_func, (void *) (stack + stack_size),
                    flags, NULL, NULL, NULL, NULL), EPERM);
}

void *empty_thread(void *arg) {
  return NULL;
}

void *spawn_thread_and_exit(void *arg) {
  pthread_t *tid = (pthread_t *) arg;
  pthread_create(tid, NULL, empty_thread, NULL);
  return NULL;
}

// This tests that clone() works OK if the parent thread immediately
// exits.
TEST(test_thread_parent_exits) {
  StartSeccompSandbox();
  pthread_t tid1;
  pthread_t tid2;
  pthread_create(&tid1, NULL, spawn_thread_and_exit, &tid2);
  pthread_join(tid1, NULL);
  pthread_join(tid2, NULL);
}

static void *fp_thread(void *x) {
  int val;
  asm("movss %%xmm0, %0" : "=m"(val));
  MSG("val=%i\n", val);
  return NULL;
}

TEST(test_fp_regs) {
  StartSeccompSandbox();
  int val = 1234;
  asm("movss %0, %%xmm0" : "=m"(val));
  pthread_t tid;
  pthread_create(&tid, NULL, fp_thread, NULL);
  pthread_join(tid, NULL);
  MSG("thread done OK\n");
}

static long long read_tsc() {
  long long rc;
  asm volatile(
      "rdtsc\n"
      "mov %%eax, (%0)\n"
      "mov %%edx, 4(%0)\n"
      :
      : "c"(&rc), "a"(-1), "d"(-1));
  return rc;
}

TEST(test_rdtsc) {
  StartSeccompSandbox();
  // Just check that we can do the instruction.
  read_tsc();
}

TEST(test_getpid) {
  pid_t pid = getpid();
  StartSeccompSandbox();
  CHECK_SUCCEEDS(pid == getpid());
  // Bypass any caching that glibc's getpid() wrapper might do.
  CHECK_SUCCEEDS(pid == syscall(__NR_getpid));
}

TEST(test_gettid) {
  // glibc doesn't provide a gettid() wrapper.
  pid_t tid;
  CHECK_SUCCEEDS((tid = syscall(__NR_gettid)) > 0);
  StartSeccompSandbox();
  CHECK_SUCCEEDS(tid == syscall(__NR_gettid));
}

static void *map_something() {
  void *addr;
  CHECK_SUCCEEDS((addr = mmap(NULL, 0x1000, PROT_READ,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) !=
                 MAP_FAILED);
  return addr;
}

TEST(test_mmap_disallows_remapping) {
  void *addr = map_something();
  StartSeccompSandbox();
  // Overwriting a mapping that was created before the sandbox was
  // enabled is not allowed.
  CHECK_ERRNO(mmap(addr, 0x1000, PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0), EINVAL);
}

TEST(test_mmap_disallows_low_address) {
  StartSeccompSandbox();
  // Mapping pages at low addresses is not allowed because this helps
  // with exploiting buggy kernels.
  CHECK_ERRNO(mmap(NULL, 0x1000, PROT_READ,
                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0), EINVAL);
}

TEST(test_munmap_allowed) {
  StartSeccompSandbox();
  void *addr = map_something();
  CHECK_SUCCEEDS(munmap(addr, 0x1000) == 0);
}

TEST(test_munmap_disallowed) {
  void *addr = map_something();
  StartSeccompSandbox();
  CHECK_ERRNO(munmap(addr, 0x1000), EINVAL);
}

TEST(test_mprotect_allowed) {
  StartSeccompSandbox();
  void *addr = map_something();
  CHECK_SUCCEEDS(mprotect(addr, 0x1000, PROT_READ | PROT_WRITE) == 0);
}

TEST(test_mprotect_disallowed) {
  void *addr = map_something();
  StartSeccompSandbox();
  CHECK_ERRNO(mprotect(addr, 0x1000, PROT_READ | PROT_WRITE), EINVAL);
}

static int get_tty_fd() {
  int master_fd, tty_fd;
  CHECK_SUCCEEDS(openpty(&master_fd, &tty_fd, NULL, NULL, NULL) == 0);
  return tty_fd;
}

TEST(test_ioctl_tiocgwinsz_allowed) {
  int tty_fd = get_tty_fd();
  StartSeccompSandbox();
  int size[2];
  // Get terminal width and height.
  CHECK_SUCCEEDS(ioctl(tty_fd, TIOCGWINSZ, size) == 0);
}

TEST(test_ioctl_disallowed) {
  int tty_fd = get_tty_fd();
  StartSeccompSandbox();
  // This ioctl call inserts a character into the tty's input queue,
  // which provides a way to send commands to an interactive shell.
  char c = 'x';
  CHECK_ERRNO(ioctl(tty_fd, TIOCSTI, &c), EINVAL);
}

TEST(test_socket) {
  StartSeccompSandbox();
  CHECK_ERRNO(socket(AF_UNIX, SOCK_STREAM, 0),
              // TODO: Make it consistent between i386 and x86-64.
              #if defined(__x86_64__)
              ENOSYS
              #elif defined(__i386__)
              EINVAL
              #else
              #error Unsupported target platform
              #endif
              );
}

TEST(test_setsockopt) {
  int sock_fd;
  CHECK_SUCCEEDS((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
  StartSeccompSandbox();
  // Check some allowed options.
  int keepalive = 1;
  CHECK_SUCCEEDS(setsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE,
			    &keepalive, sizeof(keepalive)) == 0);
  int cork = 1;
  CHECK_SUCCEEDS(setsockopt(sock_fd, IPPROTO_TCP, TCP_CORK,
			    &cork, sizeof(cork)) == 0);
  // Check some disallowed options.
  int passcred = 1;
  CHECK_ERRNO(setsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED,
  			 &passcred, sizeof(passcred)) == -1, EINVAL);
  // All the documented TCP_* flags are allowed, so make up a number.
  int unknown = 1;
  CHECK_ERRNO(setsockopt(sock_fd, IPPROTO_TCP, 0x123456,
  			 &unknown, sizeof(unknown)) == -1, EINVAL);
}

TEST(test_getsockopt) {
  int sock_fd;
  CHECK_SUCCEEDS((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1);
  StartSeccompSandbox();
  // Pass a larger sized buffer than necessary to check that the
  // actual size gets returned OK.
  char buf[100];
  socklen_t size;
  // Check some allowed options.
  size = sizeof(buf);
  CHECK_SUCCEEDS(getsockopt(sock_fd, SOL_SOCKET, SO_KEEPALIVE,
			    buf, &size) == 0);
  CHECK(size == sizeof(int));
  size = sizeof(buf);
  CHECK_SUCCEEDS(getsockopt(sock_fd, IPPROTO_TCP, TCP_CORK,
			    buf, &size) == 0);
  CHECK(size == sizeof(int));
  // Check some disallowed options.
  size = sizeof(buf);
  CHECK_ERRNO(getsockopt(sock_fd, SOL_SOCKET, SO_PASSCRED,
  			 buf, &size) == -1, EINVAL);
  // All the documented TCP_* flags are allowed, so make up a number.
  size = sizeof(buf);
  CHECK_ERRNO(getsockopt(sock_fd, IPPROTO_TCP, 0x123456,
  			 buf, &size) == -1, EINVAL);
}

TEST(test_open_disabled) {
  StartSeccompSandbox();
  CHECK_ERRNO(open("/dev/null", O_RDONLY), EACCES);

  // Writing to the policy flag does not change this.
  playground::g_policy.allow_file_namespace = true;
  CHECK_ERRNO(open("/dev/null", O_RDONLY), EACCES);
}

TEST(test_open_enabled) {
  playground::g_policy.allow_file_namespace = true;
  StartSeccompSandbox();

  int fd;
  CHECK_SUCCEEDS((fd = open("/dev/null", O_RDONLY)) >= 0);
  CHECK_SUCCEEDS(close(fd) == 0);

  CHECK_ERRNO(open("/dev/null", O_WRONLY), EACCES);
  CHECK_ERRNO(open("/dev/null", O_RDWR), EACCES);
}

TEST(test_access_disabled) {
  StartSeccompSandbox();
  CHECK_ERRNO(access("/dev/null", R_OK), EACCES);
}

TEST(test_access_enabled) {
  playground::g_policy.allow_file_namespace = true;
  StartSeccompSandbox();
  CHECK_SUCCEEDS(access("/dev/null", R_OK) == 0);
  CHECK_ERRNO(access("path-that-does-not-exist", R_OK), ENOENT);
}

TEST(test_stat_disabled) {
  StartSeccompSandbox();
  struct stat st;
  CHECK_ERRNO(stat("/dev/null", &st), EACCES);
}

TEST(test_stat_enabled) {
  playground::g_policy.allow_file_namespace = true;
  StartSeccompSandbox();
  struct stat st;
  CHECK_SUCCEEDS(stat("/dev/null", &st) == 0);
  CHECK_ERRNO(stat("path-that-does-not-exist", &st), ENOENT);
}

// TODO(mseaborn): It would be good to test the error cases for the
// sandbox's treatment of SysV SHM.  However, that leads to leaks of
// SysV shared memory segments, because the sandbox prevents us from
// freeing a segment with shmctl() if it gets a SysV-related error.
TEST(test_sysv_shared_memory) {
  StartSeccompSandbox();
  int shmid;
  CHECK_SUCCEEDS((shmid = shmget(IPC_PRIVATE, 0x1000, 0700)) != -1);
  void *addr;
  CHECK_SUCCEEDS((addr = shmat(shmid, NULL, 0)) != MAP_FAILED);
  // Check that we can access the memory we mapped.
  memset(addr, 1, 0x1000);
  CHECK_SUCCEEDS(shmdt(addr) == 0);
  CHECK_SUCCEEDS(shmctl(shmid, IPC_RMID, NULL) == 0);
}

static int g_value;

static void signal_handler(int sig) {
  g_value = 300;
  MSG("In signal handler\n");
}

static void sigaction_handler(int sig, siginfo_t *a, void *b) {
  g_value = 300;
  MSG("In sigaction handler\n");
}

static void (*g_sig_handler_ptr)(int sig, void *addr) asm("g_sig_handler_ptr");

static void non_fatal_sig_handler(int sig, void *addr) {
  g_value = 300;
  MSG("Caught signal %d at %p\n", sig, addr);
}

static void fatal_sig_handler(int sig, void *addr) {
  // Recursively trigger another segmentation fault while already in the SEGV
  // handler. This should terminate the program if SIGSEGV is marked as a
  // deferred signal.
  // Only do this on the first entry to this function. Otherwise, the signal
  // handler was probably marked as SA_NODEFER and we want to continue
  // execution.
  if (!g_value++) {
    MSG("Caught signal %d at %p\n", sig, addr);
    if (sig == SIGSEGV) {
      asm volatile("hlt");
    } else {
      asm volatile("int3");
    }
  }
}

static void (*generic_signal_handler(void))
  (int signo, siginfo_t *info, void *context) {
  void (*hdl)(int, siginfo_t *, void *);
  asm volatile(
    "lea  0f, %0\n"
    "jmp  999f\n"
  "0:\n"

#if defined(__x86_64__)
    "mov  0xB0(%%rsp), %%rsi\n"    // Pass original %rip to signal handler
    "cmpb $0xF4, 0(%%rsi)\n"       // hlt
    "jnz   1f\n"
    "addq $1, 0xB0(%%rsp)\n"       // Adjust %eip past failing instruction
  "1:jmp  *g_sig_handler_ptr\n"    // Call actual signal handler
#elif defined(__i386__)
    // TODO(markus): We currently don't guarantee that signal handlers always
    //               have the correct "magic" restorer function. If we fix
    //               this, we should add a test for it (both for SEGV and
    //               non-SEGV).
    "cmpw $0, 0xA(%%esp)\n"
    "lea  0x40(%%esp), %%eax\n"    // %eip at time of exception
    "jz   1f\n"
    "add  $0x9C, %%eax\n"          // %eip at time of exception
  "1:mov  0(%%eax), %%ecx\n"
    "cmpb $0xF4, 0(%%ecx)\n"       // hlt
    "jnz   2f\n"
    "addl $1, 0(%%eax)\n"          // Adjust %eip past failing instruction
  "2:push %%ecx\n"                 // Pass original %eip to signal handler
    "mov  8(%%esp), %%eax\n"
    "push %%eax\n"                 // Pass signal number to signal handler
    "call *g_sig_handler_ptr\n"    // Call actual signal handler
    "pop  %%eax\n"
    "pop  %%ecx\n"
    "ret\n"
#else
#error Unsupported target platform
#endif

"999:\n"
    : "=r"(hdl));
  return hdl;
}

TEST(test_signal_handler) {
  CHECK_SUCCEEDS(signal(SIGTRAP, signal_handler) != SIG_ERR);

  StartSeccompSandbox();

  CHECK_SUCCEEDS(signal(SIGTRAP, signal_handler) != SIG_ERR);

  g_value = 200;
  asm("int3");
  CHECK(g_value == 300);
}

TEST(test_sigaction_handler) {
  struct sigaction act;
  act.sa_sigaction = sigaction_handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_SIGINFO;
  CHECK_SUCCEEDS(sigaction(SIGTRAP, &act, NULL) == 0);

  StartSeccompSandbox();

  CHECK_SUCCEEDS(sigaction(SIGTRAP, &act, NULL) == 0);

  g_value = 200;
  asm("int3");
  CHECK(g_value == 300);
}

TEST(test_blocked_signal) {
  CHECK_SUCCEEDS(signal(SIGTRAP, signal_handler) != SIG_ERR);
  StartSeccompSandbox();

  // Initially the signal should not be blocked.
  sigset_t sigs;
  sigfillset(&sigs);
  CHECK_SUCCEEDS(sigprocmask(0, NULL, &sigs) == 0);
  CHECK(!sigismember(&sigs, SIGTRAP));

  sigemptyset(&sigs);
  sigaddset(&sigs, SIGTRAP);
  CHECK_SUCCEEDS(sigprocmask(SIG_BLOCK, &sigs, NULL) == 0);

  // Check that we can read back the blocked status.
  sigemptyset(&sigs);
  CHECK_SUCCEEDS(sigprocmask(0, NULL, &sigs) == 0);
  CHECK(sigismember(&sigs, SIGTRAP));

  // Check that the signal handler really is blocked.
  intend_exit_status(SIGTRAP, true);
  asm("int3");
}

TEST(test_sigaltstack) {
  // The sandbox does not support sigaltstack() yet.  Just test that
  // it returns an error.
  StartSeccompSandbox();
  stack_t st;
  st.ss_size = 0x4000;
  CHECK_SUCCEEDS((st.ss_sp = malloc(st.ss_size)) != NULL);
  st.ss_flags = 0;
  CHECK_ERRNO(sigaltstack(&st, NULL), ENOSYS);
}

TEST(test_sa_flags) {
  StartSeccompSandbox();
  int flags[4] = { 0, SA_NODEFER, SA_SIGINFO, SA_SIGINFO | SA_NODEFER };
  for (int i = 0; i < 4; ++i) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = generic_signal_handler();
    g_sig_handler_ptr = non_fatal_sig_handler;
    sa.sa_flags = flags[i];

    // Test SEGV handling
    g_value = 200;
    sigaction(SIGSEGV, &sa, NULL);
    asm volatile("hlt");
    CHECK(g_value == 300);

    // Test non-SEGV handling
    g_value = 200;
    sigaction(SIGTRAP, &sa, NULL);
    asm volatile("int3");
    CHECK(g_value == 300);
  }
}

TEST(test_segv_defer) {
  StartSeccompSandbox();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = generic_signal_handler();
  g_sig_handler_ptr = fatal_sig_handler;

  // Test non-deferred SEGV (should continue execution)
  sa.sa_flags = SA_NODEFER;
  sigaction(SIGSEGV, &sa, NULL);
  g_value = 0;
  asm volatile("hlt");

  // Test deferred SEGV (should terminate program)
  sa.sa_flags = 0;
  sigaction(SIGSEGV, &sa, NULL);
  g_value = 0;
  intend_exit_status(SIGSEGV, true);
  asm volatile("hlt");
}

TEST(test_trap_defer) {
  StartSeccompSandbox();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = generic_signal_handler();
  g_sig_handler_ptr = fatal_sig_handler;

  // Test non-deferred TRAP (should continue execution)
  sa.sa_flags = SA_NODEFER;
  sigaction(SIGTRAP, &sa, NULL);
  g_value = 0;
  asm volatile("int3");

  // Test deferred TRAP (should terminate program)
  sa.sa_flags = 0;
  sigaction(SIGTRAP, &sa, NULL);
  g_value = 0;
  intend_exit_status(SIGTRAP, true);
  asm volatile("int3");
}

TEST(test_segv_resethand) {
  StartSeccompSandbox();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = generic_signal_handler();
  g_sig_handler_ptr = non_fatal_sig_handler;
  sa.sa_flags = SA_RESETHAND;
  sigaction(SIGSEGV, &sa, NULL);

  // Test first invocation of signal handler (should continue execution)
  asm volatile("hlt");

  // Test second invocation of signal handler (should terminate program)
  intend_exit_status(SIGSEGV, true);
  asm volatile("hlt");
}

TEST(test_trap_resethand) {
  StartSeccompSandbox();
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = generic_signal_handler();
  g_sig_handler_ptr = non_fatal_sig_handler;
  sa.sa_flags = SA_RESETHAND;
  sigaction(SIGTRAP, &sa, NULL);

  // Test first invocation of signal handler (should continue execution)
  asm volatile("int3");

  // Test second invocation of signal handler (should terminate program)
  intend_exit_status(SIGTRAP, true);
  asm volatile("int3");
}

TEST(test_debugging) {
#ifndef NDEBUG
  // We will be inspecting the debugging output that the sandbox writes to
  // stderr. But we still want to make sure that our CHECK() macro can
  // write messages that the user can read. Move glibc's stderr variable
  // to a different file descriptor.
  int new_stderr;
  CHECK_SUCCEEDS((new_stderr = dup(2)) != -1);
  CHECK_SUCCEEDS((stderr = fdopen(new_stderr, "a")) != NULL);

  int pipe_fds[2];
  CHECK_SUCCEEDS(pipe(pipe_fds) == 0);
  CHECK_SUCCEEDS(dup2(pipe_fds[1], 2) == 2);
  playground::Debug::enable();
  StartSeccompSandbox();
  CHECK_SUCCEEDS(close(pipe_fds[1]) == 0);
  char buf[4096];
  ssize_t sz;
  CHECK_SUCCEEDS((sz = read(pipe_fds[0], buf, sizeof(buf)-1)) > 0);
  buf[sz] = '\000';
  CHECK(strstr(buf, "close:"));
#endif
}

TEST(test_prctl) {
  CHECK_SUCCEEDS(prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
  CHECK_SUCCEEDS(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
  int fds[2];
  CHECK_SUCCEEDS(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
  pid_t pid;
  CHECK_SUCCEEDS((pid = fork()) >= 0);
  char ch = 0;
  if (pid == 0) {
    StartSeccompSandbox();
    read(fds[0], &ch, 1);
    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
    write(fds[0], &ch, 1);
    read(fds[0], &ch, 1);
    _exit(1);
  }
  CHECK_ERRNO(ptrace(PTRACE_ATTACH, pid, 0, 0), EPERM);
  write(fds[1], &ch, 1);
  read(fds[1], &ch, 1);
  CHECK_SUCCEEDS(ptrace(PTRACE_ATTACH, pid, 0, 0) == 0);

  // Now clean up.  We have to collect the subprocess's stopped state
  // with waitpid() otherwise PTRACE_KILL will not successfully kill
  // the subprocess.
  int status;
  CHECK_SUCCEEDS(waitpid(pid, &status, 0) == pid);
  CHECK(WIFSTOPPED(status));
  CHECK(WSTOPSIG(status) == SIGSTOP);

  CHECK_SUCCEEDS(ptrace(PTRACE_KILL, pid, 0, 0) == 0);

  CHECK_SUCCEEDS(waitpid(pid, &status, 0) == pid);
  CHECK(WIFSIGNALED(status));
  CHECK(WTERMSIG(status) == SIGKILL);
}

TEST(test_syscall_entrypoint_var) {
  StartSeccompSandbox();

  // Tests that we can in fact call embedded system calls generated by
  // linux_syscall_support.h. If the system call doesn't get detected and
  // wrapped by the sandbox, the kernel would automatically terminate us.
  // This is most likely going to result in the test hanging.
  sys_gettid();
}

// In order to read from a pointer that might not be valid, we use the
// trick of getting the kernel to do it on our behalf.
static bool safe_memcpy(void *dest, void *src, int size) {
  // This is only guaranteed to work, if we don't stuff more than one page
  // of data into the kernel's buffers. If we ever needed more, we have to
  // break things up into smaller parts.
  CHECK(size <= 4096);

  static int fds[2] = { -1, -1 };
  if (fds[0] == -1) {
    CHECK_SUCCEEDS(pipe(fds) == 0);
  }

  int written;
  CHECK_MAYFAIL((written = write(fds[1], src, size)) == size, EFAULT);
  if (written != size) {
    CHECK_ERRNO(written, EFAULT);
    return false;
  } else {
    CHECK_SUCCEEDS(read(fds[0], dest, size) == size);
    return true;
  }
}

TEST(test_backtrace) {
  // Verify that a backtrace of a redirected system call has the expected
  // stack frame.
  // In particular, we expect to see a chain of frame pointers that is
  // terminated by a 0xDEADBEEF marker. And we expect that right below this
  // marker, we can find a return address that points back to the where
  // the intercepted system call originated.
  //
  // First we make ourselves dumpable, so that we can use ptrace() for the
  // rest of this test.
  CHECK_SUCCEEDS(prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == 0);
  int fds[2];

  // Create a socketpair() that we will use to a) block the child process,
  // and b) dereference pointers that might possibly be invalid.
  CHECK_SUCCEEDS(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

  // Create child process that we can then analyze as it is setting up the
  // sandbox.
  pid_t pid;
  CHECK_SUCCEEDS((pid = fork()) >= 0);
  char ch = 0;
  if (pid == 0) {
    // Start the sandbox and block on a read() call. Different versions of
    // glibc do different things when invoking system calls. In order to
    // eliminate this external dependeny, use linux_syscall_support.h to
    // set up our system call.
    StartSeccompSandbox();
    sys_read(fds[0], &ch, 1);

    // We will never get here.
    _exit(1);
  }

  // We don't know when the sandbox is done initializing. So, just keep
  // checking our child every so often.
  for (;;) {
    // Attach to the child process.
    CHECK_SUCCEEDS(ptrace(PTRACE_ATTACH, pid, 0, 0) == 0);
    int status;
    CHECK_SUCCEEDS(waitpid(pid, &status, 0) == pid);
    CHECK(WIFSTOPPED(status));
    CHECK(WSTOPSIG(status) == SIGSTOP);

    // Read the integer CPU registers.
    struct user user;
    memset(&user, 0, sizeof(user));
    CHECK_SUCCEEDS(ptrace(PTRACE_GETREGS, pid, 0, &user) == 0);
    #if defined(__x86_64__)
    unsigned long sp = user.regs.rsp;
    unsigned long bp = user.regs.rbp;
    unsigned long ax = user.regs.orig_rax;
    #elif defined(__i386__)
    unsigned long sp = user.regs.esp;
    unsigned long bp = user.regs.ebp;
    unsigned long ax = user.regs.orig_eax;
    #else
    #error Unsupported target platform
    #endif

    // We expect to be inside of a read() system call.
    if (ax == __NR_read) {
      // Look at the top four stack frames. We guarantee that the sandbox
      // never pushes more than four stack frames when intercepting system
      // calls.
      for (int i = 0; i < 4; ++i) {
        // If we haven't finished initializing the sandbox, we might have an
        // invalid stack pointer.
        if (!sp || sp == (unsigned long)-1L) {
          break;
        }

        // Basic sanity check for the frame pointer.
        if (sp > bp) {
          break;
        }

        // Follow the chain of frame pointers until we find the 0xDEADBEEF
        // marker.
        unsigned long new_bp = ptrace(PTRACE_PEEKDATA, pid, bp, 0);
        if (new_bp ==
            (sizeof(new_bp) == 4 ? 0xDEADBEEFul : 0xDEADBEEFDEADBEEFull)) {
          // Right below the marker is the real frame pointer and then the
          // next stack slot is our original return address (not the return
          // address into the instrumented code).
          unsigned long ip = ptrace(PTRACE_PEEKDATA, pid,
                                    bp + 2*sizeof(void *), 0);

          // We know the code snippet that linux_syscall_support.h generates,
          // so we can tell where we would expect to find the kernel entry
          // (i.e. INT $0x80 or SYSCALL).
          //
          // We should look for this instruction in the parent process instead
          // of the child. We don't want to be confused if the sandbox tried
          // to rewrite the code (this shouldn't happen for
          // linux_syscall_support.h, but will happen for other system calls).
          #if defined(__x86_64__)
          void *insn_addr = (void *)(ip + 2);
          unsigned short expected_insn = 0x050F; /* SYSCALL */
          #elif defined(__i386__)
          void *insn_addr = (void *)(ip - 2);
          unsigned short expected_insn = 0x80CD; /* INT $0x80 */
          #else
          #error Unsupported target platform
          #endif
          unsigned short insn = 0;
          if (!safe_memcpy(&insn, insn_addr, sizeof(insn)) ||
              insn != expected_insn) {
            break;
          }

          // Everything is OK, kill the child process and finish the test.
          CHECK_SUCCEEDS(ptrace(PTRACE_KILL, pid, 0, 0) == 0);
  
          CHECK_SUCCEEDS(waitpid(pid, &status, 0) == pid);
          CHECK(WIFSIGNALED(status));
          CHECK(WTERMSIG(status) == SIGKILL);

          return;
        }

        // Another sanity check for the frame pointer.
        if (new_bp < bp) {
          break;
        }

        // Now follow the chain of frame pointers to the next stack frame.
        sp = bp;
        bp = new_bp;
      }
    }

    // The child hasn't completed initialization of the sandbox just yet.
    CHECK_SUCCEEDS(ptrace(PTRACE_DETACH, pid, 0, 0) == 0);

    // Try again in 20ms.
    CHECK_SUCCEEDS(poll(NULL, 0, 20) == 0);
  }
}

TEST(test_fdatasync) {
  StartSeccompSandbox();
  int fds[2];
  CHECK_SUCCEEDS(pipe(fds) == 0);
  CHECK_ERRNO(fdatasync(fds[0]), EINVAL);
  CHECK_ERRNO(fsync(fds[0]), ENOSYS);
}

struct testcase {
  const char *test_name;
  void (*test_func)();
};

struct testcase all_tests[] = {
#include "test-list.h"
  { NULL, NULL },
};

static int run_test_forked(struct testcase *test) {
  printf("** %s\n", test->test_name);
  int pipe_fds[2];
  CHECK_SUCCEEDS(pipe(pipe_fds) == 0);
  pid_t pid;
  CHECK_SUCCEEDS((pid = fork()) >= 0);
  if (pid == 0) {
    CHECK_SUCCEEDS(close(pipe_fds[0]) == 0);
    g_intended_status_fd = pipe_fds[1];

    test->test_func();
    intend_exit_status(0, false);
    _exit(0);
  }
  CHECK_SUCCEEDS(close(pipe_fds[1]) == 0);

  int intended_status;
  int got = read(pipe_fds[0], &intended_status, sizeof(intended_status));
  bool got_intended_status = got == sizeof(intended_status);
  if (!got_intended_status) {
    printf("Test runner: Did not receive intended status\n");
  }

  int status;
  CHECK_SUCCEEDS(waitpid(pid, &status, 0) == pid);
  if (!got_intended_status) {
    printf("Test returned exit status %i\n", status);
    return 1;
  }
  else if ((status & ~WCOREFLAG) != intended_status) {
    printf("Test failed with exit status %i, expected %i\n",
           status, intended_status);
    return 1;
  }
  else {
    return 0;
  }
}

static int run_test_by_name(const char *name) {
  struct testcase *test;
  for (test = all_tests; test->test_name != NULL; test++) {
    if (strcmp(name, test->test_name) == 0) {
      printf("Running test %s...\n", name);
      test->test_func();
      printf("OK\n");
      return 0;
    }
  }
  fprintf(stderr, "Test '%s' not found\n", name);
  return 1;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  // Set a modest limit on the stack size, so that if we trigger
  // infinite recursion during the tests we do not trash the system by
  // triggering the OOM killer.
  struct rlimit limit;
  CHECK_SUCCEEDS(getrlimit(RLIMIT_STACK, &limit) == 0);
  limit.rlim_cur = MIN(limit.rlim_cur, 1024 * 1024);
  CHECK_SUCCEEDS(setrlimit(RLIMIT_STACK, &limit) == 0);

  if (getenv("SECCOMP_SANDBOX_REFERENCE_IMPL")) {
    // Insecure version, for development purposes.
    playground::g_create_trusted_thread =
      playground::CreateReferenceTrustedThread;
  }

  if (argc == 2) {
    // Run one test without forking, to aid debugging.
    return run_test_by_name(argv[1]);
  }
  else if (argc > 2) {
    // TODO: run multiple tests.
    fprintf(stderr, "Too many arguments\n");
    return 1;
  }
  else {
    // Run all tests.
    struct testcase *test;
    int failures = 0;
    for (test = all_tests; test->test_name != NULL; test++) {
      failures += run_test_forked(test);
    }
    if (failures == 0) {
      printf("OK\n");
      return 0;
    }
    else {
      printf("%i FAILURE(S)\n", failures);
      return 1;
    }
  }
}
