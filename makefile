CFLAGS = -g -O0 -Wall -Werror -Wextra -Wno-missing-field-initializers         \
         -Wno-unused-parameter -I.
LDFLAGS = -g
CPPFLAGS =
DEPFLAGS = -MMD -MF $@.d
MODS := allocator preload library debug maps x86_decode securemem sandbox     \
        syscall_entrypoint system_call_table                                  \
        trusted_thread trusted_thread_asm trusted_process                     \
        access exit fault_handler_asm clone                                   \
        getpid gettid ioctl ipc madvise mmap mprotect                         \
        munmap open prctl reference_trusted_thread sigaction sigprocmask      \
        socketcall stat tls_setup tls_setup_helper
OBJS64 := $(shell echo ${MODS} | xargs -n 1 | sed -e 's/$$/.o64/')
OBJS32 := $(shell echo ${MODS} | xargs -n 1 | sed -e 's/$$/.o32/')
ALL_OBJS = $(OBJS32) $(OBJS64) tests/test_syscalls.o64 tests/test_syscalls.o32 \
           tests/clone_test_helper.o64 tests/clone_test_helper.o32 \
           timestats.o playground.o
DEP_FILES = $(wildcard $(foreach f,$(ALL_OBJS),$(f).d))

include $(DEP_FILES)

.SUFFIXES: .o64 .o32

all: testbin timestats demo

clean:
	-rm -f playground playground.o
	-rm -f $(ALL_OBJS)
	-rm -f $(DEP_FILES)
	-rm -f preload64.so
	-rm -f preload32.so
	-rm -f testbin64 testbin.o64
	-rm -f testbin32 testbin.o32
	-rm -f timestats timestats.o
	-rm -f run_tests_32 run_tests_64
	-rm -f tests/test-list.h
	-rm -f core core.* vgcore vgcore.* strace.log*

test: run_tests_64 run_tests_32
	./run_tests_64
	./run_tests_32
	env SECCOMP_SANDBOX_REFERENCE_IMPL=1 ./run_tests_64
	env SECCOMP_SANDBOX_REFERENCE_IMPL=1 ./run_tests_32

tests/test_syscalls.o64 tests/test_syscalls.o32: tests/test-list.h

tests/test-list.h: tests/list_tests.py tests/test_syscalls.cc
	python tests/list_tests.py tests/test_syscalls.cc > $@

run_tests_64: $(OBJS64) tests/test_syscalls.o64 tests/clone_test_helper.o64
	g++ -m64 $^ -lpthread -lutil -o $@
run_tests_32: $(OBJS32) tests/test_syscalls.o32 tests/clone_test_helper.o32
	g++ -m32 $^ -lpthread -lutil -o $@

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

timestats: timestats.o
	${CXX} ${LDFLAGS} -o $@ $<

testbin64: test.cc ${OBJS64}
	${CXX} ${CFLAGS} ${CPPFLAGS} -m64 -c -o testbin.o64 $<
	${CXX} ${LDFLAGS} -m64 -o testbin64 testbin.o64 ${OBJS64} -lpthread -ldl

testbin32: test.cc ${OBJS32}
	${CXX} ${CFLAGS} ${CPPFLAGS} -m32 -c -o testbin.o32 $<
	${CXX} ${LDFLAGS} -m32 -o testbin32 testbin.o32 ${OBJS32} -lpthread -ldl

playground: playground.o
	${CXX} ${LDFLAGS} -o $@ $<

.cc.o:
	${CXX} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -c -o $@ $<

preload64.so: ${OBJS64}
	${CXX} ${LDFLAGS} -m64 -shared -o $@ $+ -lpthread

preload32.so: ${OBJS32}
	${CXX} ${LDFLAGS} -m32 -shared -o $@ $+ -lpthread

.cc.o64:
	${CXX} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -m64 -fPIC -c -o $@ $<

.c.o64:
	${CC} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -m64 --std=gnu99 -fPIC \
		-c -o $@ $<

.S.o64:
	${CC} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -m64 -c -o $@ $<

.cc.o32:
	${CXX} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -m32 -fPIC -c -o $@ $<

.c.o32:
	${CC} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -m32 --std=gnu99 -fPIC \
		-c -o $@ $<

.S.o32:
	${CC} ${CFLAGS} ${CPPFLAGS} ${DEPFLAGS} -m32 -c -o $@ $<
