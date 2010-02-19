CFLAGS = -g -O0 -Wall -Werror
LDFLAGS = -g
CPPFLAGS =
MODS := preload library debug maps x86_decode securemem sandbox syscall       \
        syscall_table trusted_thread trusted_process                          \
        access exit clone getpid gettid ioctl ipc madvise mmap mprotect       \
        munmap open socketcall stat
OBJS64 := $(shell echo ${MODS} | xargs -n 1 | sed -e 's/$$/.o64/')
OBJS32 := $(shell echo ${MODS} | xargs -n 1 | sed -e 's/$$/.o32/')
HEADERS:= $(shell for i in ${MODS}; do [ -r "$$i" ] && echo "$$i"; done)

.SUFFIXES: .o64 .o32

all: testbin demo

clean:
	-rm -f playground playground.o
	-rm -f preload64.so *.o64
	-rm -f preload32.so *.o32
	-rm -f testbin64 testbin.o64
	-rm -f testbin32 testbin.o32
	-rm -f core core.* vgcore vgcore.* strace.log*

demo: playground preload32.so preload64.so
	./playground /bin/ls $(HOME)

testbin: testbin32 testbin64

gdb: testbin64
	gdb $<

valgrind: testbin64
	valgrind --db-attach=yes ./$<

strace: testbin32
	@rm -f strace.log*
	strace -ff -o strace.log ./$< &
	@/bin/bash -c 'sleep 0.25; sed -e "/In secure mode/q;d" <(tail -f $$(ls strace.log*|head -n 1))'
	multitail -mb 1GB -CS strace strace.log*

testbin64: test.cc ${OBJS64}
	${CXX} ${CFLAGS} ${CPPFLAGS} -c -o testbin.o64 $<
	${CXX} ${LDFLAGS} -o testbin64 testbin.o64 ${OBJS64} -lpthread -ldl

testbin32: test.cc ${OBJS32}
	${CXX} ${CFLAGS} ${CPPFLAGS} -m32 -c -o testbin.o32 $<
	${CXX} ${LDFLAGS} -m32 -o testbin32 testbin.o32 ${OBJS32} -lpthread -ldl

playground: playground.o
	${CXX} ${LDFLAGS} -o $@ $<

.cc.o: ${HEADERS}
	${CXX} ${CFLAGS} ${CPPFLAGS} -c -o $@ $<

preload64.so: ${OBJS64}
	${CXX} ${LDFLAGS} -shared -o $@ $+ -lpthread

preload32.so: ${OBJS32}
	${CXX} ${LDFLAGS} -m32 -shared -o $@ $+ -lpthread

.cc.o64: ${HEADERS}
	${CXX} ${CFLAGS} ${CPPFLAGS} -fPIC -c -o $@ $<

.c.o64: ${HEADERS}
	${CC} ${CFLAGS} ${CPPFLAGS} --std=gnu99 -fPIC -c -o $@ $<

.cc.o32: ${HEADERS}
	${CXX} ${CFLAGS} ${CPPFLAGS} -m32 -fPIC -c -o $@ $<

.c.o32: ${HEADERS}
	${CC} ${CFLAGS} ${CPPFLAGS} -m32 --std=gnu99 -fPIC -c -o $@ $<
