#ifndef MAPS_H__
#define MAPS_H__

#include <elf.h>
#include <vector>

#if __WORDSIZE == 64
typedef Elf64_Addr Elf_Addr;
#else
typedef Elf32_Addr Elf_Addr;
#endif

namespace playground {

class Library;
class Maps {
  friend class Library;
 public:
  Maps(const std::string& maps_file);
  ~Maps();

 protected:
  char *forwardGetRequest(Library *library, Elf_Addr offset, char *buf,
                          size_t length) const;
  std::string forwardGetRequest(Library *library, Elf_Addr offset) const;

  typedef std::map<std::string, Library> LibraryMap;
  friend class Iterator;
  class Iterator {
    friend class Maps;

   protected:
    explicit Iterator(Maps* maps);
    Iterator(Maps* maps, bool at_beginning, bool at_end);
    Maps::LibraryMap::iterator& getIterator() const;

   public:
    Iterator begin();
    Iterator end();
    Iterator& operator++();
    Iterator operator++(int i);
    Library* operator*() const;
    bool operator==(const Iterator& iter) const;
    bool operator!=(const Iterator& iter) const;

   protected:
    mutable LibraryMap::iterator iter_;
    Maps *maps_;
    bool at_beginning_;
    bool at_end_;
  };

 public:
  typedef class Iterator const_iterator;

  const_iterator begin() {
    return begin_iter_;
  }

  const_iterator end() {
    return end_iter_;
  }

  char* allocNearAddr(char *addr, size_t size, int prot) const;

  char* vsyscall() const { return vsyscall_; }

 private:
  struct Request {
    enum Type { REQ_GET, REQ_GET_STR };

    Request() { }

    Request(enum Type t, Library* i, Elf_Addr o, size_t l) :
        library(i), offset(o), length(l), type(t), padding(0) {
    }

    Library*   library;
    Elf_Addr   offset;
    size_t     length;
    enum Type  type;
    int        padding; // for valgrind
  };

 protected:
  std::string maps_file_;
  Iterator    begin_iter_;
  Iterator    end_iter_;
  LibraryMap  libs_;
  pid_t       pid_;
  int         fds_[2];
  char*       vsyscall_;
};

} // namespace

#endif // MAPS_H__
