CC = gcc
CLANG ?= clang-14
LLVM_STRIP ?= llvm-strip
PARSE_TRACE ?= $(abspath ../parse_trace/target/release/parse_trace)

LINUX_USR ?= $(abspath ../linux/usr/include)
LIBBPF_PATH ?= $(abspath ../linux/tools/lib/bpf)
MOD_PATH ?= $(abspath ../mod)

CFLAGS += -I${LINUX_USR} -I${LIBBPF_PATH} -I${MOD_PATH}
CFLAGS += -pipe -O2 -march=native -std=gnu11

LDFLAGS += -Wl,-O1 -Wl,--as-needed
LDFLAGS += -L${LIBBPF_PATH} -l:libbpf.a -lelf -lz

BPF_CFLAGS += -I${LINUX_USR} -I${LIBBPF_PATH} -I${MOD_PATH}
BPF_CFLAGS += -D__EBPF__ -target bpf -O2 -g -fno-stack-protector

.PHONY: clean

all: policy policy_kern.o trace trace_kern.o policy_ret policy_ret_kern.o

policy: policy_user.c traces.inc
	${CC} ${CFLAGS} -o $@ $< ${LDFLAGS}

policy_ret: policy_ret_user.c traces.rev
	${CC} ${CFLAGS} -o $@ $< ${LDFLAGS}

policy_kern.o: policy_kern.c traces.inc
	${CLANG} ${BPF_CFLAGS} -c $< -o - | ${LLVM_STRIP} -g -o $@ -

policy_ret_kern.o: policy_ret_kern.c traces.rev
	${CLANG} ${BPF_CFLAGS} -c $< -o - | ${LLVM_STRIP} -g -o $@ -

trace: trace_user.c traces.sample
	${CC} ${CFLAGS} -o $@ $< ${LDFLAGS}

trace_kern.o: trace_kern.c
	${CLANG} ${BPF_CFLAGS} -c $< -o - | ${LLVM_STRIP} -g -o $@ -

traces.inc: trace_data.txt
	${PARSE_TRACE} -m generate-inc ../linux/System.map trace_data.txt uname

traces.rev: trace_data_ret.txt
	${PARSE_TRACE} -m generate-rev ../linux/System.map trace_data_ret.txt uname

clean:
	rm -rf policy policy_kern.o traces.inc traces.rev trace trace_kern.o policy_ret policy_ret_kern.o
