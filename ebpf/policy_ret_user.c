#define _DEFAULT_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <bpf.h>
#include <libbpf.h>

#include <ekcfi.h>

#include "traces.rev"

#define ARRAY_LEN(arr) sizeof(arr) / sizeof(arr[0])

static int ekcfi_attach(int prog_fd, int index)
{
	int ret = 0, proc_fd;
	union ekcfi_attr attr = { 
		.prog_fd = prog_fd,
		.index = index
	};

	proc_fd = open("/proc/ekcfi", O_RDWR|O_CLOEXEC);
	if (proc_fd < 0) {
		perror("open");
		return -1;
	}

	if (ioctl(proc_fd, EKCFI_ATTACH_BPF, &attr) < 0) {
		perror("ioctl");
		ret = -1;
	}

	close(proc_fd);
	return ret;
}

int main(int argc, char *argv[])
{
	char filename[256];
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	int ret = 0, i, map_fd, prog_fd;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 1;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		ret = 1;
		goto obj_close;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "ret_map");
	if (map_fd < 0) {
		printf("ERROR: finding ret_map in object file failed\n");
		ret = 1;
		goto obj_close;
	}
	for (i = 0; i < ARRAY_LEN(call_trace); i++) {
		unsigned callee_key = (unsigned)(call_trace[i].callee & 0xFFFFFFFF);
		unsigned long long *callers = call_trace[i].callers;
		if (bpf_map_update_elem(map_fd, &callee_key, callers, BPF_ANY)) {
			perror("bpf_map_update_elem");
			ret = 1;
			goto obj_close;
		}
	}

	prog = bpf_object__find_program_by_name(obj, "ebpf_ekcfi_ret_check");
	if (!prog) {
		fprintf(stderr, "ERROR: finding ebpf_ekcfi_ret_check in object file failed\n");
		ret = 1;
		goto obj_close;
	}

	prog_fd = bpf_program__fd(prog);

	if (ekcfi_attach(prog_fd, 1) < 0) {
		fprintf(stderr, "ERROR: ekcfi_attach failed\n");
		ret = 1;
	}

	// At this point our module is holding the prog refcnt

obj_close:
	bpf_object__close(obj);
	return ret;
}
