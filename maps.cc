#include <errno.h>
#include <fcntl.h>
#include <iostream>
#include <linux/unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "library.h"
#include "maps.h"
#include "sandbox_impl.h"

namespace playground {

Maps::Maps(const std::string& maps_file) :
    maps_file_(maps_file),
    begin_iter_(this, true, false),
    end_iter_(this, false, true),
    vsyscall_(0) {
  int fd = open(maps_file.c_str(), O_RDONLY);
  Sandbox::SysCalls sys;
  if (fd >= 0) {
    char buf[256] = { 0 };
    int len = 0, rc = 1;
    bool long_line = false;
    do {
      if (rc > 0) {
        rc = Sandbox::read(sys, fd, buf + len, sizeof(buf) - len - 1);
        if (rc > 0) {
          len += rc;
        }
      }
      char *ptr = buf;
      if (!long_line) {
        long_line = true;
        unsigned long start = strtoul(ptr, &ptr, 16);
        unsigned long stop = strtoul(ptr + 1, &ptr, 16);
        while (*ptr == ' ' || *ptr == '\t') ++ptr;
        char *perm_ptr = ptr;
        while (*ptr && *ptr != ' ' && *ptr != '\t') ++ptr;
        std::string perm(perm_ptr, ptr - perm_ptr);
        unsigned long offset = strtoul(ptr, &ptr, 16);
        while (*ptr == ' ' || *ptr == '\t') ++ptr;
        char *id_ptr = ptr;
        unsigned major = static_cast<unsigned>(strtoul(ptr, &ptr, 16));
        while (*ptr == ':') ++ptr;
        unsigned minor = static_cast<unsigned>(strtoul(ptr, &ptr, 16));
        while (*ptr && *ptr != ' ' && *ptr != '\t') ++ptr;
        unsigned long inode = strtoul(ptr, &ptr, 10);
        while (*ptr && *ptr != ' ' && *ptr != '\t') ++ptr;
        std::string id(id_ptr, ptr - id_ptr);
        while (*ptr == ' ' || *ptr == '\t') ++ptr;
        char *library_ptr = ptr;
        while (*ptr && *ptr != ' ' && *ptr != '\t' && *ptr != '\n') ++ptr;
        std::string library(library_ptr, ptr - library_ptr);
        bool isVDSO = false;
        if (library == "[vdso]") {
          // /proc/self/maps has a misleading file offset in the [vdso] entry.
          // Override it with a sane value.
          offset = 0;
          isVDSO = true;
        } else if (library == "[vsyscall]") {
          vsyscall_ = reinterpret_cast<char *>(start);
        } else if (library.empty() || library[0] == '[') {
          goto skip_entry;
        }
        int prot = 0;
        if (perm.find('r') != std::string::npos) {
          prot |= PROT_READ;
        }
        if (perm.find('w') != std::string::npos) {
          prot |= PROT_WRITE;
        }
        if (perm.find('x') != std::string::npos) {
          prot |= PROT_EXEC;
        }
        if ((prot & (PROT_EXEC | PROT_READ)) == 0) {
          goto skip_entry;
        }
        Library* lib = &libs_[id + ' ' + library];
        lib->setLibraryInfo(this, library, major, minor, inode);
        lib->addMemoryRange(reinterpret_cast<void *>(start),
                            reinterpret_cast<void *>(stop),
                            Elf_Addr(offset),
                            prot, isVDSO);
      }
   skip_entry:
      for (;;) {
        if (!*ptr || *ptr++ == '\n') {
          long_line = false;
          memmove(buf, ptr, len - (ptr - buf));
          memset(buf + len - (ptr - buf), 0, ptr - buf);
          len -= (ptr - buf);
          break;
        }
      }
    } while (len || long_line);
    NOINTR_SYS(close(fd));
  }
}

Maps::Iterator::Iterator(Maps* maps, bool at_beginning, bool at_end)
    : maps_(maps),
      at_beginning_(at_beginning),
      at_end_(at_end) {
}

Maps::LibraryMap::iterator& Maps::Iterator::getIterator() const {
  if (at_beginning_) {
    iter_ = maps_->libs_.begin();
  } else if (at_end_) {
    iter_ = maps_->libs_.end();
  }
  return iter_;
}

Maps::Iterator Maps::Iterator::begin() {
  return maps_->begin_iter_;
}

Maps::Iterator Maps::Iterator::end() {
  return maps_->end_iter_;
}

Maps::Iterator& Maps::Iterator::operator++() {
  getIterator().operator++();
  at_beginning_ = false;
  return *this;
}

Maps::Iterator Maps::Iterator::operator++(int i) {
  getIterator().operator++(i);
  at_beginning_ = false;
  return *this;
}

Library* Maps::Iterator::operator*() const {
  return &getIterator().operator*().second;
}

bool Maps::Iterator::operator==(const Maps::Iterator& iter) const {
  return getIterator().operator==(iter.getIterator());
}

bool Maps::Iterator::operator!=(const Maps::Iterator& iter) const {
  return !operator==(iter);
}

std::string Maps::Iterator::name() const {
  return getIterator()->first;
}

char* Maps::allocNearAddr(char* addr, size_t size, int prot) const {
  // We try to allocate memory within 1.5GB of a target address. This means,
  // we will be able to perform relative 32bit jumps from the target address.
  size = (size + 4095) & ~4095;
  Sandbox::SysCalls sys;
  int fd = sys.open(maps_file_.c_str(), O_RDONLY, 0);
  if (fd < 0) {
    return NULL;
  }

  char buf[256] = { 0 };
  int len = 0, rc = 1;
  bool long_line = false;
  unsigned long gap_start = 0x10000;
  char *new_addr;
  do {
    if (rc > 0) {
      do {
        rc = Sandbox::read(sys, fd, buf + len, sizeof(buf) - len - 1);
        if (rc > 0) {
          len += rc;
        }
      } while (rc > 0 && len < (int)sizeof(buf) - 1);
    }
    char *ptr = buf;
    if (!long_line) {
      long_line = true;
      unsigned long start = strtoul(ptr, &ptr, 16);
      unsigned long stop = strtoul(ptr + 1, &ptr, 16);
      if (start - gap_start >= size) {
        if (reinterpret_cast<long>(addr) - static_cast<long>(start) >= 0) {
          if (reinterpret_cast<long>(addr) - (start - size) < (1536 << 20)) {
            new_addr = reinterpret_cast<char *>(sys.MMAP
                           (reinterpret_cast<void *>(start - size), size, prot,
                            MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0));
            if (new_addr != MAP_FAILED) {
              goto done;
            }
          }
        } else if (gap_start + size - reinterpret_cast<long>(addr) <
                   (1536 << 20)) {
          new_addr = reinterpret_cast<char *>(sys.MMAP
                         (reinterpret_cast<void *>(gap_start), size, prot,
                          MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1 ,0));
          if (new_addr != MAP_FAILED) {
            goto done;
          }
        }
      }
      gap_start = stop;
    }
    for (;;) {
      if (!*ptr || *ptr++ == '\n') {
        long_line = false;
        memmove(buf, ptr, len - (ptr - buf));
        memset(buf + len - (ptr - buf), 0, ptr - buf);
        len -= (ptr - buf);
        break;
      }
    }
  } while (len || long_line);
  new_addr = NULL;
done:
  sys.close(fd);
  return new_addr;
}

} // namespace
