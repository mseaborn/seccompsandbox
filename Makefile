MODS := preload library maps x86_decode securemem sandbox syscall             \
        syscall_table trusted_thread trusted_process                          \
        clone getpid ioctl mmap mprotect munmap open stat
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
	./playground /bin/ls /home/markus

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
	${CXX} -c -Werror -Wall -g -O0 -o testbin.o64 $<
	${CXX} -g -o testbin64 testbin.o64 ${OBJS64} -lpthread

testbin32: test.cc ${OBJS32}
	/usr/crosstool/v12/gcc-4.3.1-glibc-2.3.6-grte/i686-unknown-linux-gnu/bin/i686-unknown-linux-gnu-g++ -c -Werror -Wall -g -O0 -o testbin.o32 $<
	/usr/crosstool/v12/gcc-4.3.1-glibc-2.3.6-grte/i686-unknown-linux-gnu/bin/i686-unknown-linux-gnu-g++ -g -o testbin32 testbin.o32 ${OBJS32} -lpthread

playground: playground.o
	${CXX} -g -o $@ $<

.cc.o: ${HEADERS}
	${CXX} -c -Werror -Wall -g -O0 -o $@ $<

preload64.so: ${OBJS64}
	${CXX} -shared -g -o $@ $+ -lpthread

preload32.so: ${OBJS32}
	/usr/crosstool/v12/gcc-4.3.1-glibc-2.3.6-grte/i686-unknown-linux-gnu/bin/i686-unknown-linux-gnu-g++ -shared -g -o $@ $+ -lpthread

.cc.o64: ${HEADERS}
	${CXX} -fPIC -Werror -Wall -g -O0 -c -o $@ $<

.c.o64: ${HEADERS}
	${CC} --std=gnu99 -fPIC -Werror -Wall -g -O0 -c -o $@ $<

.cc.o32: ${HEADERS}
	/usr/crosstool/v12/gcc-4.3.1-glibc-2.3.6-grte/i686-unknown-linux-gnu/bin/i686-unknown-linux-gnu-g++ -fPIC -Werror -Wall -g -O0 -c -o $@ $<

.c.o32: ${HEADERS}
	/usr/crosstool/v12/gcc-4.3.1-glibc-2.3.6-grte/i686-unknown-linux-gnu/bin/i686-unknown-linux-gnu-gcc --std=gnu99 -fPIC -Werror -Wall -g -O0 -c -o $@ $<
