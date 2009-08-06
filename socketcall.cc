#include "debug.h"
#include "sandbox_impl.h"

namespace playground {

#if defined(__x86_64__)

ssize_t Sandbox::sandbox_recvfrom(int sockfd, void* buf, size_t len, int flags,
                                  void* from, socklen_t* fromlen) {
  Debug::syscall(__NR_recvfrom, "Executing handler");

  SysCalls sys;
  if (!from && !flags) {
    // recv() with a NULL sender and no flags is the same as read(), which
    // is unrestricted in seccomp mode.
    Debug::message("Replaced recv() with call to read()");
    ssize_t rc = sys.read(sockfd, buf, len);
    if (rc < 0) {
      return -sys.my_errno;
    } else {
      return rc;
    }
  }

  struct {
    int       sysnum;
    long long cookie;
    RecvFrom  recvfrom_req;
  } __attribute__((packed)) request;
  request.sysnum               = __NR_recvfrom;
  request.cookie               = cookie();
  request.recvfrom_req.sockfd  = sockfd;
  request.recvfrom_req.buf     = buf;
  request.recvfrom_req.len     = len;
  request.recvfrom_req.flags   = flags;
  request.recvfrom_req.from    = from;
  request.recvfrom_req.fromlen = fromlen;

  long rc;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward recvfrom() request [sandbox]");
  }
  return static_cast<int>(rc);
}

ssize_t Sandbox::sandbox_recvmsg(int sockfd, struct msghdr* msg, int flags) {
  Debug::syscall(__NR_recvmsg, "Executing handler");

  // We cannot simplify recvmsg() to recvfrom(), recv() or read(), as we do
  // not know whether the caller needs us to set msg->msg_flags.
  struct {
    int       sysnum;
    long long cookie;
    RecvMsg   recvmsg_req;
  } __attribute__((packed)) request;
  request.sysnum             = __NR_recvmsg;
  request.cookie             = cookie();
  request.recvmsg_req.sockfd = sockfd;
  request.recvmsg_req.msg    = msg;
  request.recvmsg_req.flags  = flags;

  long rc;
  SysCalls sys;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward recvmsg() request [sandbox]");
  }
  return static_cast<int>(rc);
}

size_t Sandbox::sandbox_sendmsg(int sockfd, const struct msghdr* msg,
                                int flags) {
  Debug::syscall(__NR_sendmsg, "Executing handler");

  if (msg->msg_iovlen == 1 && msg->msg_controllen == 0) {
    // sendmsg() can sometimes be simplified as sendto()
    return sandbox_sendto(sockfd, msg->msg_iov, msg->msg_iovlen,
                          flags, msg->msg_name, msg->msg_namelen);
  }

  struct {
    int           sysnum;
    long long     cookie;
    SendMsg       sendmsg_req;
    struct msghdr msg;
  } __attribute__((packed)) request;
  request.sysnum             = __NR_sendmsg;
  request.cookie             = cookie();
  request.sendmsg_req.sockfd = sockfd;
  request.sendmsg_req.msg    = msg;
  request.sendmsg_req.flags  = flags;
  request.msg                = *msg;

  long rc;
  SysCalls sys;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward sendmsg() request [sandbox]");
  }
  return static_cast<int>(rc);
}

ssize_t Sandbox::sandbox_sendto(int sockfd, const void* buf, size_t len,
                                int flags, const void* to, socklen_t tolen) {
  Debug::syscall(__NR_sendto, "Executing handler");

  SysCalls sys;
  if (!to && !flags) {
    // sendto() with a NULL recipient and no flags is the same as write(),
    // which is unrestricted in seccomp mode.
    Debug::message("Replaced sendto() with call to write()");
    ssize_t rc = sys.write(sockfd, buf, len);
    if (rc < 0) {
      return -sys.my_errno;
    } else {
      return rc;
    }
  }

  struct {
    int       sysnum;
    long long cookie;
    SendTo    sendto_req;
  } __attribute__((packed)) request;
  request.sysnum            = __NR_sendto;
  request.cookie            = cookie();
  request.sendto_req.sockfd = sockfd;
  request.sendto_req.buf    = buf;
  request.sendto_req.len    = len;
  request.sendto_req.flags  = flags;
  request.sendto_req.to     = to;
  request.sendto_req.tolen  = tolen;

  long rc;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward sendto() request [sandbox]");
  }
  return static_cast<int>(rc);
}

int Sandbox::sandbox_setsockopt(int sockfd, int level, int optname,
                                const void* optval, socklen_t optlen) {
  Debug::syscall(__NR_setsockopt, "Executing handler");

  struct {
    int        sysnum;
    long long  cookie;
    SetSockOpt setsockopt_req;
  } __attribute__((packed)) request;
  request.sysnum                 = __NR_setsockopt;
  request.cookie                 = cookie();
  request.setsockopt_req.sockfd  = sockfd;
  request.setsockopt_req.level   = level;
  request.setsockopt_req.optname = optname;
  request.setsockopt_req.optval  = optval;
  request.setsockopt_req.optlen  = optlen;

  long rc;
  SysCalls sys;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward setsockopt() request [sandbox]");
  }
  return static_cast<int>(rc);
}

int Sandbox::sandbox_getsockopt(int sockfd, int level, int optname,
                                void* optval, socklen_t* optlen) {
  Debug::syscall(__NR_getsockopt, "Executing handler");

  struct {
    int        sysnum;
    long long  cookie;
    GetSockOpt getsockopt_req;
  } __attribute__((packed)) request;
  request.sysnum                 = __NR_getsockopt;
  request.cookie                 = cookie();
  request.getsockopt_req.sockfd  = sockfd;
  request.getsockopt_req.level   = level;
  request.getsockopt_req.optname = optname;
  request.getsockopt_req.optval  = optval;
  request.getsockopt_req.optlen  = optlen;

  long rc;
  SysCalls sys;
  if (write(sys, processFdPub(), &request, sizeof(request)) !=
      sizeof(request) ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward getsockopt() request [sandbox]");
  }
  return static_cast<int>(rc);
}

bool Sandbox::process_recvfrom(int parentProc, int sandboxFd, int threadFdPub,
                               int threadFd, SecureMem::Args* mem) {
  // Read request
  RecvFrom recvfrom_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &recvfrom_req, sizeof(recvfrom_req)) !=
      sizeof(recvfrom_req)) {
    die("Failed to read parameters for recvfrom() [process]");
  }

  // Unsupported flag encountered. Deny the call.
  if (recvfrom_req.flags &
      ~(MSG_DONTWAIT|MSG_OOB|MSG_PEEK|MSG_TRUNC|MSG_WAITALL)) {
    SecureMem::abandonSystemCall(threadFd, -EINVAL);
    return false;
  }

  // While we do not anticipate any particular need to receive data on
  // unconnected sockets, there is no particular risk in doing so.
  SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                            __NR_recvfrom, recvfrom_req.sockfd,
                            recvfrom_req.buf, recvfrom_req.len,
                            recvfrom_req.flags, recvfrom_req.from,
                            recvfrom_req.fromlen);
  return true;
}

bool Sandbox::process_recvmsg(int parentProc, int sandboxFd, int threadFdPub,
                              int threadFd, SecureMem::Args* mem) {
  // Read request
  RecvMsg  recvmsg_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &recvmsg_req, sizeof(recvmsg_req)) !=
      sizeof(recvmsg_req)) {
    die("Failed to read parameters for recvmsg() [process]");
  }

  // Unsupported flag encountered. Deny the call.
  if (recvmsg_req.flags &
      ~(MSG_DONTWAIT|MSG_OOB|MSG_PEEK|MSG_TRUNC|MSG_WAITALL)) {
    SecureMem::abandonSystemCall(threadFd, -EINVAL);
    return false;
  }

  // Receiving messages is general not security critical.
  SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                            __NR_recvmsg, recvmsg_req.sockfd,
                            recvmsg_req.msg, recvmsg_req.flags);
  return true;
}

bool Sandbox::process_sendmsg(int parentProc, int sandboxFd, int threadFdPub,
                              int threadFd, SecureMem::Args* mem) {
  // Read request
  struct {
    SendMsg sendmsg_req;
    struct msghdr   msg;
  } __attribute__((packed)) data;
  SysCalls sys;
  if (read(sys, sandboxFd, &data, sizeof(data)) != sizeof(data)) {
    die("Failed to read parameters for sendmsg() [process]");
  }

  // The trusted process receives file handles when a new untrusted thread
  // gets created. We have security checks in place that prevent any
  // critical information from being tampered with during thread creation.
  // But if we disallow passing of file handles, this adds an extra hurdle
  // for an attacker. So, unless the sandboxed code needs the ability to
  // pass file handles, we should disallow doing so.
  if (data.msg.msg_name || data.msg.msg_control ||
      (data.sendmsg_req.flags &
       ~(MSG_CONFIRM|MSG_DONTWAIT|MSG_EOR|MSG_MORE|MSG_NOSIGNAL|MSG_OOB))) {
    SecureMem::abandonSystemCall(threadFd, -EINVAL);
    return false;
  }

  // This must be a locked system call, because we have to ensure that the
  // untrusted code does not tamper with the msghdr after we have examined it.
  SecureMem::lockSystemCall(parentProc, mem);
  memcpy(mem->pathname, &data.msg, sizeof(struct msghdr));
  SecureMem::sendSystemCall(threadFdPub, true, parentProc, mem,
                            __NR_sendmsg, data.sendmsg_req.sockfd,
                            mem->pathname - (char*)mem + (char*)mem->self,
                            data.sendmsg_req.flags);
  return true;
}

bool Sandbox::process_sendto(int parentProc, int sandboxFd, int threadFdPub,
                             int threadFd, SecureMem::Args* mem) {
  // Read request
  SendTo   sendto_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &sendto_req, sizeof(sendto_req)) !=
      sizeof(sendto_req)) {
    die("Failed to read parameters for sendto() [process]");
  }

  // The sandbox does not allow sending to arbitrary addresses.
  if (sendto_req.to) {
    SecureMem::abandonSystemCall(threadFd, -EINVAL);
    return false;
  }

  // Unsupported flag encountered. Deny the call.
  if (sendto_req.flags &
      ~(MSG_CONFIRM|MSG_DONTWAIT|MSG_EOR|MSG_MORE|MSG_NOSIGNAL|MSG_OOB)) {
    SecureMem::abandonSystemCall(threadFd, -EINVAL);
    return false;
  }

  // Sending data on a connected socket is similar to calling write().
  // Allow it.
  SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                            __NR_sendto, sendto_req.sockfd,
                            sendto_req.buf, sendto_req.len,
                            sendto_req.flags, sendto_req.to,
                            sendto_req.tolen);
  return true;
}

bool Sandbox::process_setsockopt(int parentProc, int sandboxFd,
                                 int threadFdPub, int threadFd,
                                 SecureMem::Args* mem) {
  // Read request
  SetSockOpt setsockopt_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &setsockopt_req, sizeof(setsockopt_req)) !=
      sizeof(setsockopt_req)) {
    die("Failed to read parameters for setsockopt() [process]");
  }

  switch (setsockopt_req.level) {
    case SOL_SOCKET:
      switch (setsockopt_req.optname) {
        case SO_KEEPALIVE:
        case SO_LINGER:
        case SO_OOBINLINE:
        case SO_RCVBUF:
        case SO_RCVLOWAT:
        case SO_SNDLOWAT:
        case SO_RCVTIMEO:
        case SO_SNDTIMEO:
        case SO_REUSEADDR:
        case SO_SNDBUF:
        case SO_TIMESTAMP:
          SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                                 __NR_setsockopt, setsockopt_req.sockfd,
                                 setsockopt_req.level, setsockopt_req.optname,
                                 setsockopt_req.optval, setsockopt_req.optlen);
          return true;
        default:
          break;
      }
      break;
    case IPPROTO_TCP:
      switch (setsockopt_req.optname) {
        case TCP_CORK:
        case TCP_DEFER_ACCEPT:
        case TCP_INFO:
        case TCP_KEEPCNT:
        case TCP_KEEPIDLE:
        case TCP_KEEPINTVL:
        case TCP_LINGER2:
        case TCP_MAXSEG:
        case TCP_NODELAY:
        case TCP_QUICKACK:
        case TCP_SYNCNT:
        case TCP_WINDOW_CLAMP:
          SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                                 __NR_setsockopt, setsockopt_req.sockfd,
                                 setsockopt_req.level, setsockopt_req.optname,
                                 setsockopt_req.optval, setsockopt_req.optlen);
          return true;
        default:
          break;
      }
      break;
    default:
      break;
  }
  SecureMem::abandonSystemCall(threadFd, -EINVAL);
  return false;
}

bool Sandbox::process_getsockopt(int parentProc, int sandboxFd,
                                 int threadFdPub, int threadFd,
                                 SecureMem::Args* mem) {
  // Read request
  GetSockOpt getsockopt_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &getsockopt_req, sizeof(getsockopt_req)) !=
      sizeof(getsockopt_req)) {
    die("Failed to read parameters for getsockopt() [process]");
  }

  switch (getsockopt_req.level) {
    case SOL_SOCKET:
      switch (getsockopt_req.optname) {
        case SO_ACCEPTCONN:
        case SO_ERROR:
        case SO_KEEPALIVE:
        case SO_LINGER:
        case SO_OOBINLINE:
        case SO_RCVBUF:
        case SO_RCVLOWAT:
        case SO_SNDLOWAT:
        case SO_RCVTIMEO:
        case SO_SNDTIMEO:
        case SO_REUSEADDR:
        case SO_SNDBUF:
        case SO_TIMESTAMP:
        case SO_TYPE:
          SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                                 __NR_getsockopt, getsockopt_req.sockfd,
                                 getsockopt_req.level, getsockopt_req.optname,
                                 getsockopt_req.optval, getsockopt_req.optlen);
          return true;
        default:
          break;
      }
      break;
    case IPPROTO_TCP:
      switch (getsockopt_req.optname) {
        case TCP_CORK:
        case TCP_DEFER_ACCEPT:
        case TCP_INFO:
        case TCP_KEEPCNT:
        case TCP_KEEPIDLE:
        case TCP_KEEPINTVL:
        case TCP_LINGER2:
        case TCP_MAXSEG:
        case TCP_NODELAY:
        case TCP_QUICKACK:
        case TCP_SYNCNT:
        case TCP_WINDOW_CLAMP:
          SecureMem::sendSystemCall(threadFdPub, false, -1, mem,
                                 __NR_getsockopt, getsockopt_req.sockfd,
                                 getsockopt_req.level, getsockopt_req.optname,
                                 getsockopt_req.optval, getsockopt_req.optlen);
          return true;
        default:
          break;
      }
      break;
    default:
      break;
  }
  SecureMem::abandonSystemCall(threadFd, -EINVAL);
  return false;
}

#elif defined(__i386__)

enum {
  SYS_SOCKET      =  1,
  SYS_BIND        =  2,
  SYS_CONNECT     =  3,
  SYS_LISTEN      =  4,
  SYS_ACCEPT      =  5,
  SYS_GETSOCKNAME =  6,
  SYS_GETPEERNAME =  7,
  SYS_SOCKETPAIR  =  8,
  SYS_SEND        =  9,
  SYS_RECV        = 10,
  SYS_SENDTO      = 11,
  SYS_RECVFROM    = 12,
  SYS_SHUTDOWN    = 13,
  SYS_SETSOCKOPT  = 14,
  SYS_GETSOCKOPT  = 15,
  SYS_SENDMSG     = 16,
  SYS_RECVMSG     = 17,
  SYS_ACCEPT4     = 18
};

struct Sandbox::SocketCallArgInfo {
  size_t len;
  off_t  addrOff;
  off_t  lengthOff;
};
const struct Sandbox::SocketCallArgInfo Sandbox::socketCallArgInfo[] = {
  #define STRUCT(s)   reinterpret_cast<Socketcall *>(0)->args.s
  #define SIZE(s)     sizeof(STRUCT(s))
  #define OFF(s, f)   offsetof(typeof STRUCT(s), f)
  { 0                                                                  },
  { SIZE(socket)                                                       },
  { SIZE(bind),       OFF(bind, addr),         OFF(bind, addrlen)      },
  { SIZE(connect),    OFF(connect, addr),      OFF(connect, addrlen)   },
  { SIZE(listen)                                                       },
  { SIZE(accept)                                                       },
  { SIZE(getsockname)                                                  },
  { SIZE(getpeername)                                                  },
  { SIZE(socketpair)                                                   },
  { SIZE(send)                                                         },
  { SIZE(recv)                                                         },
  { SIZE(sendto),     OFF(sendto, to),         OFF(sendto, tolen)      },
  { SIZE(recvfrom)                                                     },
  { SIZE(shutdown)                                                     },
  { SIZE(setsockopt), OFF(setsockopt, optval), OFF(setsockopt, optlen) },
  { SIZE(getsockopt)                                                   },
  { SIZE(sendmsg)                                                      },
  { SIZE(recvmsg)                                                      },
  { SIZE(accept4)                                                      }
  #undef STRUCT
  #undef SIZE
  #undef OFF
};

int Sandbox::sandbox_socketcall(int call, void* args) {
  Debug::syscall(__NR_socketcall, "Executing handler", call);

  // When demultiplexing socketcall(), only accept calls that have a valid
  // "call" opcode.
  if (call < SYS_SOCKET || call > SYS_ACCEPT4) {
    return -ENOSYS;
  }

  // Some type of calls include a pointer to an address or name, which cannot
  // be accessed by the trusted process, as it lives in a separate address
  // space. For these calls, append the extra data to the serialized request.
  // This requires some copying of data, as we have to make sure there is
  // only a single atomic call to write().
  socklen_t   numExtraData  = 0;
  const void* extraDataAddr = NULL;
  if (socketCallArgInfo[call].lengthOff) {
    memcpy(&numExtraData,
           reinterpret_cast<char *>(args) + socketCallArgInfo[call].lengthOff,
           sizeof(socklen_t));
    extraDataAddr = reinterpret_cast<char *>(args) +
                    socketCallArgInfo[call].addrOff;
  }

  // sendmsg() and recvmsg() have more complicated requirements for computing
  // the amount of extra data that needs to be sent to the trusted process.
  if (call == SYS_SENDMSG) {
    SendMsg *sendmsg_args = reinterpret_cast<SendMsg *>(args);
    if (sendmsg_args->msg->msg_iovlen == 1 &&
        !sendmsg_args->msg->msg_control) {
      // This sendmsg() call will be simplified to a sendto() call
      numExtraData  = sendmsg_args->msg->msg_namelen;
      extraDataAddr = sendmsg_args->msg->msg_name;
    } else {
      numExtraData  = sizeof(*sendmsg_args->msg);
      extraDataAddr = sendmsg_args->msg;
    }
  }
  if (call == SYS_RECVMSG) {
    RecvMsg *recvmsg_args = reinterpret_cast<RecvMsg *>(args);
    if (recvmsg_args->msg->msg_iovlen == 1 &&
        !recvmsg_args->msg->msg_control) {
      // This recvmsg() call will be simplified to a recvfrom() call
      numExtraData  = 0;
      extraDataAddr = NULL;
    } else {
      numExtraData  = sizeof(*recvmsg_args->msg);
      extraDataAddr = recvmsg_args->msg;
    }
  }

  // Set up storage for the request header and copy the data from "args"
  // into it.
  struct Request {
    int        sysnum;
    long long  cookie;
    Socketcall socketcall_req;
  } __attribute__((packed)) *request;
  char data[sizeof(struct Request) + numExtraData];
  request = reinterpret_cast<struct Request *>(data);
  memcpy(&request->socketcall_req.args, args, socketCallArgInfo[call].len);

  // Simplify send(), sendto() and sendmsg(), if there are simpler equivalent
  // calls. This allows us to occasionally replace them with calls to write(),
  // which don't have to be forwarded to the trusted process.
  SysCalls sys;
  if (call == SYS_SENDMSG &&
      request->socketcall_req.args.sendmsg.msg->msg_iovlen == 1 &&
      !request->socketcall_req.args.sendmsg.msg->msg_control) {
    // Ordering of these assignments is important, as we are reshuffling
    // fields inside of a union.
    call = SYS_SENDTO;
    request->socketcall_req.args.sendto.flags =
        request->socketcall_req.args.sendmsg.flags;
    request->socketcall_req.args.sendto.to    =
        request->socketcall_req.args.sendmsg.msg->msg_name;
    request->socketcall_req.args.sendto.tolen =
        request->socketcall_req.args.sendmsg.msg->msg_namelen;
    request->socketcall_req.args.sendto.len   =
        request->socketcall_req.args.sendmsg.msg->msg_iov->iov_len;
    request->socketcall_req.args.sendto.buf   =
        request->socketcall_req.args.sendmsg.msg->msg_iov->iov_base;
  }
  if (call == SYS_SENDTO && !request->socketcall_req.args.sendto.to) {
    // sendto() with a NULL address is the same as send()
    call         = SYS_SEND;
    numExtraData = 0;
  }
  if (call == SYS_SEND && !request->socketcall_req.args.send.flags) {
    // send() with no flags is the same as write(), which is unrestricted
    // in seccomp mode.
    Debug::message("Replaced socketcall() with call to write()");
    ssize_t rc = sys.write(request->socketcall_req.args.send.sockfd,
                           request->socketcall_req.args.send.buf,
                           request->socketcall_req.args.send.len);
    if (rc < 0) {
      return -sys.my_errno;
    } else {
      return rc;
    }
  }

  // Simplify recv(), and recvfrom(), if there are simpler equivalent calls.
  // This allows us to occasionally replace them with calls to read(), which
  // don't have to be forwarded to the trusted process.
  // We cannot simplify recvmsg() to recvfrom(), recv() or read(), as we do
  // not know whether the caller needs us to set msg->msg_flags.
  if (call == SYS_RECVFROM && !request->socketcall_req.args.recvfrom.from) {
    // recvfrom() with a NULL address buffer is the same as recv()
    call = SYS_RECV;
  }
  if (call == SYS_RECV && !request->socketcall_req.args.recv.flags) {
    // recv() with no flags is the same as read(), which is unrestricted
    // in seccomp mode.
    Debug::message("Replaced socketcall() with call to read()");
    ssize_t rc = sys.read(request->socketcall_req.args.recv.sockfd,
                          request->socketcall_req.args.recv.buf,
                          request->socketcall_req.args.recv.len);
    if (rc < 0) {
      return -sys.my_errno;
    } else {
      return rc;
    }
  }

  // Fill in the rest of the request header.
  request->sysnum                 = __NR_socketcall;
  request->cookie                 = cookie();
  request->socketcall_req.call    = call;
  request->socketcall_req.arg_ptr = args;
  int padding = sizeof(request->socketcall_req.args) -
                socketCallArgInfo[call].len;
  if (padding > 0) {
    memset((char *)(&request->socketcall_req.args + 1) - padding, 0, padding);
  }
  if (extraDataAddr) {
    memcpy(request + 1, extraDataAddr, numExtraData);
  }

  // Send request to trusted process and collect response from trusted thread.
  long rc;
  ssize_t len                     = sizeof(struct Request) + numExtraData;
  if (write(sys, processFdPub(), data, len) != len ||
      read(sys, threadFdPub(), &rc, sizeof(rc)) != sizeof(rc)) {
    die("Failed to forward socketcall() request [sandbox]");
  }
  return static_cast<int>(rc);
}

bool Sandbox::process_socketcall(int parentProc, int sandboxFd,
                                 int threadFdPub, int threadFd,
                                 SecureMem::Args* mem) {
  // Read request
  Socketcall socketcall_req;
  SysCalls sys;
  if (read(sys, sandboxFd, &socketcall_req, sizeof(socketcall_req)) !=
      sizeof(socketcall_req)) {
    die("Failed to read parameters for socketcall() [process]");
  }

  // sandbox_socketcall() should never send us an unexpected "call" opcode.
  // If it did, something went very wrong and we better terminate the process.
  if (socketcall_req.call < SYS_SOCKET || socketcall_req.call > SYS_ACCEPT4) {
    die("Unexpected socketcall() [process]");
  }

  // Check if this particular operation carries an extra payload.
  socklen_t numExtraData = 0;
  if (socketCallArgInfo[socketcall_req.call].lengthOff) {
    memcpy(&numExtraData,
           reinterpret_cast<char *>(&socketcall_req) +
           socketCallArgInfo[socketcall_req.call].lengthOff,
           sizeof(socklen_t));
  } else if (socketcall_req.call == SYS_SENDMSG) {
    numExtraData  = sizeof(*socketcall_req.args.sendmsg.msg);
  } else if (socketcall_req.call == SYS_RECVMSG) {
    numExtraData  = sizeof(*socketcall_req.args.recvmsg.msg);
  }

  // Verify that the length for the payload is reasonable. We don't want to
  // blow up our stack, and excessive (or negative) buffer sizes are almost
  // certainly a bug.
  if (numExtraData < 0 || numExtraData > 4096) {
    die("Unexpected size for socketcall() payload [process]");
  }

  // Read the extra payload, if any.
  char extra[numExtraData];
  if (numExtraData) {
    if (read(sys, sandboxFd, extra, numExtraData) != (ssize_t)numExtraData) {
      die("Failed to read socketcall() payload [process]");
    }
  }

  int rc = -EINVAL;
  switch (socketcall_req.call) {
    case SYS_SOCKET:
      // The sandbox does not allow creation of any new sockets.
      goto deny;
    case SYS_BIND:
      // The sandbox does not allow binding an address to a socket.
      goto deny;
    case SYS_CONNECT:
      // The sandbox does not allow connecting a socket.
      goto deny;
    case SYS_LISTEN:
      // The sandbox does not allow a socket to enter listening state.
      goto deny;
    case SYS_ACCEPT4:
    case SYS_ACCEPT:
      // If the sandbox obtained a socket that is already in the listening
      // state (e.g. because somebody sent it a suitable file descriptor), it
      // is permissible to call accept().

    accept_simple:
      // None of the parameters need to be checked, so it is OK to refer
      // to the parameter block created by the untrusted code.
      SecureMem::sendSystemCall(threadFdPub, false, -1, mem, __NR_socketcall,
                                socketcall_req.call, socketcall_req.arg_ptr);
      return true;
    case SYS_GETSOCKNAME:
    case SYS_GETPEERNAME:
      // Querying the local and the remote name is not considered security
      // sensitive for the purposes of the sandbox.
      goto accept_simple;
    case SYS_SOCKETPAIR:
      // Socket pairs are connected to each other and not considered
      // security sensitive.
      goto accept_simple;
    case SYS_SENDTO:
      if (socketcall_req.args.sendto.to) {
        // The sandbox does not allow sending to arbitrary addresses.
        goto deny;
      }
      // Fall through
    case SYS_SEND:
      if (socketcall_req.args.send.flags &
          ~(MSG_CONFIRM|MSG_DONTWAIT|MSG_EOR|MSG_MORE|MSG_NOSIGNAL|MSG_OOB)) {
        // Unsupported flag encountered. Deny the call.
        goto deny;
      }
      // Sending data on a connected socket is similar to calling write().
      // Allow it.

    accept_complex:
      // The parameter block contains potentially security critical information
      // that should not be tampered with after it has been inspected. Copy it
      // into the write-protected securely shared memory before telling the
      // trusted thread to execute the socket call.
      SecureMem::lockSystemCall(parentProc, mem);
      memcpy(mem->pathname, &socketcall_req.args, sizeof(socketcall_req.args));
      SecureMem::sendSystemCall(threadFdPub, true, parentProc, mem,
                                __NR_socketcall, socketcall_req.call,
                                mem->pathname - (char*)mem + (char*)mem->self);
      return true;
    case SYS_RECVFROM:
      // While we do not anticipate any particular need to receive data on
      // unconnected sockets, there is no particular risk in doing so.
      // Fall through
    case SYS_RECV:
      if (socketcall_req.args.recv.flags &
          ~(MSG_DONTWAIT|MSG_OOB|MSG_PEEK|MSG_TRUNC|MSG_WAITALL)) {
        // Unsupported flag encountered. Deny the call.
        goto deny;
      }
      // Receiving data on a connected socket is similar to calling read().
      // Allow it.
      goto accept_complex;
    case SYS_SHUTDOWN:
      // Shutting down a socket is always OK.
      goto accept_simple;
    case SYS_SETSOCKOPT:
      switch (socketcall_req.args.setsockopt.level) {
        case SOL_SOCKET:
          switch (socketcall_req.args.setsockopt.optname) {
            case SO_KEEPALIVE:
            case SO_LINGER:
            case SO_OOBINLINE:
            case SO_RCVBUF:
            case SO_RCVLOWAT:
            case SO_SNDLOWAT:
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            case SO_REUSEADDR:
            case SO_SNDBUF:
            case SO_TIMESTAMP:
              goto accept_complex;
            default:
              break;
          }
          break;
        case IPPROTO_TCP:
          switch (socketcall_req.args.setsockopt.optname) {
            case TCP_CORK:
            case TCP_DEFER_ACCEPT:
            case TCP_INFO:
            case TCP_KEEPCNT:
            case TCP_KEEPIDLE:
            case TCP_KEEPINTVL:
            case TCP_LINGER2:
            case TCP_MAXSEG:
            case TCP_NODELAY:
            case TCP_QUICKACK:
            case TCP_SYNCNT:
            case TCP_WINDOW_CLAMP:
              goto accept_complex;
            default:
              break;
          }
          break;
        default:
          break;
      }
      goto deny;
    case SYS_GETSOCKOPT:
      switch (socketcall_req.args.getsockopt.level) {
        case SOL_SOCKET:
          switch (socketcall_req.args.getsockopt.optname) {
            case SO_ACCEPTCONN:
            case SO_ERROR:
            case SO_KEEPALIVE:
            case SO_LINGER:
            case SO_OOBINLINE:
            case SO_RCVBUF:
            case SO_RCVLOWAT:
            case SO_SNDLOWAT:
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            case SO_REUSEADDR:
            case SO_SNDBUF:
            case SO_TIMESTAMP:
            case SO_TYPE:
              goto accept_complex;
            default:
              break;
          }
          break;
        case IPPROTO_TCP:
          switch (socketcall_req.args.getsockopt.optname) {
            case TCP_CORK:
            case TCP_DEFER_ACCEPT:
            case TCP_INFO:
            case TCP_KEEPCNT:
            case TCP_KEEPIDLE:
            case TCP_KEEPINTVL:
            case TCP_LINGER2:
            case TCP_MAXSEG:
            case TCP_NODELAY:
            case TCP_QUICKACK:
            case TCP_SYNCNT:
            case TCP_WINDOW_CLAMP:
              goto accept_complex;
            default:
              break;
          }
          break;
        default:
          break;
      }
      goto deny;
    case SYS_SENDMSG: {
      // The trusted process receives file handles when a new untrusted thread
      // gets created. We have security checks in place that prevent any
      // critical information from being tampered with during thread creation.
      // But if we disallow passing of file handles, this adds an extra hurdle
      // for an attacker. So, unless the sandboxed code needs the ability to
      // pass file handles, we should disallow doing so.
      struct msghdr* msg = reinterpret_cast<struct msghdr*>(extra);
      if (msg->msg_name || msg->msg_control ||
          (socketcall_req.args.sendmsg.flags &
           ~(MSG_CONFIRM|MSG_DONTWAIT|MSG_EOR|MSG_MORE|MSG_NOSIGNAL|MSG_OOB))){
        goto deny;
      }
      SecureMem::lockSystemCall(parentProc, mem);
      socketcall_req.args.sendmsg.msg =
          reinterpret_cast<struct msghdr*>(mem->pathname +
                                           sizeof(socketcall_req.args) -
                                           (char*)mem + (char*)mem->self);
      memcpy(mem->pathname, &socketcall_req.args, sizeof(socketcall_req.args));
      memcpy(mem->pathname + sizeof(socketcall_req.args), msg, sizeof(*msg));
      SecureMem::sendSystemCall(threadFdPub, true, parentProc, mem,
                                __NR_socketcall, socketcall_req.call,
                                mem->pathname - (char*)mem + (char*)mem->self);
      return true;
    }
    case SYS_RECVMSG:
      // Receiving messages is general not security critical.
      if (socketcall_req.args.recvmsg.flags &
          ~(MSG_DONTWAIT|MSG_OOB|MSG_PEEK|MSG_TRUNC|MSG_WAITALL)) {
        goto deny;
      }
      goto accept_complex;
    default:
    deny:
      SecureMem::abandonSystemCall(threadFd, rc);
      return false;
  }
}

#else
#error Unsupported target platform
#endif

} // namespace
