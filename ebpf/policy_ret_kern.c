#include <linux/bpf.h>

#include <bpf_helpers.h>

#include <ekcfi.h>

#include "traces.rev" // defines NR_CALLEES and call_map

#define TASK_COMM_LEN 16

const char task_name[] = "uname";

SEC("tracepoint/ekcfi/ekcfi_check")
int ebpf_ekcfi_ret_check(struct ekcfi_ctx *ctx)
{
	char task_comm[16];
	__u32 callee_key;
	__u64 *callers;
	int i;

	// We only want to check for a specific program
	bpf_get_current_comm(task_comm, sizeof(task_comm));
	if (bpf_strncmp(task_comm, sizeof(task_comm), task_name))
		return EKCFI_RET_ALLOW;

	// Grab the call information from call_map
	callee_key = (__u32)(ctx->callee & 0xFFFFFFFF);
	callers = bpf_map_lookup_elem(&ret_map, &callee_key);

	// Log and allow if we do not have this callsite information
	if (!callers) {
		bpf_printk("Unknown return site 0x%llx, target=0x%llx\n",
			ctx->callee, ctx->caller);
		return EKCFI_RET_ALLOW;
	}

	// Check if caller matches
	for (i = 0; i < NR_CALLERS && callers[i]; i++) {
		if (ctx->caller == callers[i])
			return EKCFI_RET_ALLOW;
	}

	// Invalid call
	return EKCFI_RET_PANIC;
}

char _license[] SEC("license") = "GPL";
