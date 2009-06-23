#ifndef SECURE_MEM_H__
#define SECURE_MEM_H__

#include <stdlib.h>

namespace playground {

class SecureMem {
 public:
  enum Mode {
    SANDBOX, MONITOR
  };

  SecureMem(size_t size) :
      size_(size), mem_(NULL) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds_)) {
      fds_[0] = -1;
      fds_[1] = -1;
    }
  }

  void SetMode(Mode mode);

  template<class T>T receiveSystemCall(int fd) {
    return (T)receiveSystemCallInternal(fd);
  }
  void abandonSystemCall(int fd, int err);
  void sendSystemCall(int fd, int syscall_num) {
    sendSystemCallInternal(fd, syscall_num);
  }
  template<class T1>
  void sendSystemCall(int fd, int syscall_num, T1 arg1) {
    sendSystemCallInternal(fd, syscall_num, (void *)arg1);
  }
  template<class T1, class T2>
  void sendSystemCall(int fd, int syscall_num, T1 arg1, T2 arg2) {
    sendSystemCallInternal(fd, syscall_num, (void *)arg1, (void *)arg2);
  }
  template<class T1, class T2, class T3>
  void sendSystemCall(int fd, int syscall_num, T1 arg1, T2 arg2, T3 arg3) {
    sendSystemCallInternal(fd, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3);
  }
  template<class T1, class T2, class T3, class T4>
  void sendSystemCall(int fd, int syscall_num, T1 arg1, T2 arg2, T3 arg3,
                      T4 arg4) {
    sendSystemCallInternal(fd, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3,
                           (void *)arg4);
  }
  template<class T1, class T2, class T3, class T4, class T5>
  void sendSystemCall(int fd, int syscall_num, T1 arg1, T2 arg2, T3 arg3,
                      T4 arg4, T5 arg5) {
    sendSystemCallInternal(fd, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3,
                           (void *)arg4, (void *)arg5);
  }
  template<class T1, class T2, class T3, class T4, class T5, class T6>
  void sendSystemCall(int fd, int syscall_num, T1 arg1, T2 arg2, T3 arg3,
                      T4 arg4, T5 arg5, T6 arg6) {
    sendSystemCallInternal(fd, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3,
                           (void *)arg4, (void *)arg5, (void *)arg6);
  }

  void* mem() const { return mem_; }

 private:
  unsigned long receiveSystemCallInternal(int fd);
  void sendSystemCallInternal(int fd, int syscall_num,
                              void *arg1 = 0, void *arg2 = 0, void *arg3 = 0,
                              void *arg4 = 0, void *arg5 = 0, void *arg6 = 0);

  int mktmpfd(const char *prefix);

  size_t size_;
  void*  mem_;
  int    fds_[2];
};

} // namespace

#endif // SECURE_MEM_H__
