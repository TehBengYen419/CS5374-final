#include <linux/bpf.h>

#include <bpf_helpers.h>

#include <ekcfi.h>

#include "traces.sample"

#define TASK_COMM_LEN 16

const char task_name[] = "uname";

SEC("tracepoint/ekcfi/ekcfi_check")
int ebpf_trace_ind_ekcfi_check(struct ekcfi_ctx *ctx)
{
	char task_comm[16];
	__u32 callee_key;
	__u64 *callers, callee;
	int i;

	bpf_get_current_comm(task_comm, sizeof(task_comm));
	if (bpf_strncmp(task_comm, sizeof(task_comm), task_name))
		return EKCFI_RET_ALLOW;

	// Just for training
	callee_key = (__u32)(ctx->caller & 0xFFFFFFFF);
	callers = bpf_map_lookup_elem(&sample_map, &callee_key);
	
	if (!callers) {
		// Log and allow if we do not have this callsite information
		bpf_printk("%s: 0x%llx => 0x%llx", task_name, ctx->caller, ctx->callee);
		return EKCFI_RET_ALLOW;
	}

	for (i = 0; i < NR_CALLERS && callers[i]; i++) {
		if (ctx->callee == callers[i])
			return EKCFI_RET_ALLOW;
	}

	//bpf_map_update_elem(&sample_map, &callee_key, &callee, BPF_ANY);
	bpf_printk("%s: 0x%llx => 0x%llx", task_name, ctx->caller, ctx->callee);

	return 0;
}

SEC("tracepoint/ekcfi/ekcfi_check")
int ebpf_trace_ret_ekcfi_check(struct ekcfi_ctx *ctx)
{
	char task_comm[16];
	__u32 callee_key;
	__u64 *callers, caller;
	int i;

	bpf_get_current_comm(task_comm, sizeof(task_comm));
	if (bpf_strncmp(task_comm, sizeof(task_comm), task_name))
		return EKCFI_RET_ALLOW;

	// Just for training
	callee_key = (__u32)(ctx->callee & 0xFFFFFFFF);
	callers = bpf_map_lookup_elem(&sample_map, &callee_key);

	if (!callers) {
		bpf_printk("%s: 0x%llx => 0x%llx", task_name, ctx->callee, ctx->caller);
		return EKCFI_RET_ALLOW;
	}

	for (i = 0; i < NR_CALLERS && callers[i]; i++) {
		if (ctx->caller == callers[i])
			return EKCFI_RET_ALLOW;
	}

	bpf_printk("%s: 0x%llx => 0x%llx", task_name, ctx->callee, ctx->caller);
	
	return 0;
}

char _license[] SEC("license") = "GPL";
