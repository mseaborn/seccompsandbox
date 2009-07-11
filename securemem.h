#ifndef SECURE_MEM_H__
#define SECURE_MEM_H__

#include <stdlib.h>

namespace playground {

class SecureMem {
 public:
  static char* generateSecureMemSnippet(char* mem, ssize_t space, int cloneFd,
                                        int flags, void* stack, int* pid,
                                        int* ctid, void* tls,
                                        void(*trustedThread)(void*));

  template<class T> static T receiveSystemCall(int err, char *mem) {
    return (T)receiveSystemCallInternal(err, mem);
  }
  static void abandonSystemCall(int fd, int err);
  static void sendSystemCall(int fd, char *mem, int syscall_num) {
    sendSystemCallInternal(fd, mem, syscall_num);
  }
  template<class T1> static
  void sendSystemCall(int fd, char *mem, int syscall_num, T1 arg1) {
    sendSystemCallInternal(fd, mem, syscall_num, (void *)arg1);
  }
  template<class T1, class T2> static
  void sendSystemCall(int fd, char *mem, int syscall_num, T1 arg1, T2 arg2) {
    sendSystemCallInternal(fd, mem, syscall_num, (void *)arg1, (void *)arg2);
  }
  template<class T1, class T2, class T3> static
  void sendSystemCall(int fd, char *mem, int syscall_num, T1 arg1, T2 arg2,
                      T3 arg3) {
    sendSystemCallInternal(fd, mem, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3);
  }
  template<class T1, class T2, class T3, class T4> static
  void sendSystemCall(int fd, char *mem, int syscall_num, T1 arg1, T2 arg2,
                      T3 arg3, T4 arg4) {
    sendSystemCallInternal(fd, mem, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3,
                           (void *)arg4);
  }
  template<class T1, class T2, class T3, class T4, class T5> static
  void sendSystemCall(int fd, char *mem, int syscall_num, T1 arg1, T2 arg2,
                      T3 arg3, T4 arg4, T5 arg5) {
    sendSystemCallInternal(fd, mem, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3,
                           (void *)arg4, (void *)arg5);
  }
  template<class T1, class T2, class T3, class T4, class T5, class T6> static
  void sendSystemCall(int fd, char *mem, int syscall_num, T1 arg1, T2 arg2,
                      T3 arg3, T4 arg4, T5 arg5, T6 arg6) {
    sendSystemCallInternal(fd, mem, syscall_num,
                           (void *)arg1, (void *)arg2, (void *)arg3,
                           (void *)arg4, (void *)arg5, (void *)arg6);
  }

 private:
  static unsigned long receiveSystemCallInternal(int err, char *mem);
  static void sendSystemCallInternal(int fd, char *mem, int syscall_num,
                                     void *arg1 = 0, void *arg2 = 0,
                                     void *arg3 = 0, void *arg4 = 0,
                                     void *arg5 = 0, void *arg6 = 0);
};

} // namespace

#endif // SECURE_MEM_H__
