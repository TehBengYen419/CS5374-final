/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/bsearch.h>
#include <linux/capability.h>
#include <linux/compiler.h>
#include <linux/filter.h>
#include <linux/memory.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/panic.h>
#include <linux/percpu-defs.h>
#include <linux/preempt.h>
#include <linux/proc_fs.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>

#include <asm/text-patching.h>

#include "ekcfi.h"

MODULE_AUTHOR("Jinghao Jia");
MODULE_LICENSE("GPL");

#define EKCFI_FILE_NAME "ekcfi"

#define EKCFI_PATCH_SIZE 5

#define NUM_TABLE 2

struct ekcfi_tbl {
	u64 *ekcfi_data;
	u64 len;
};

static struct ekcfi_tbl __rcu *ekcfi_tbl[NUM_TABLE] __read_mostly;
static bool et_enabled[NUM_TABLE] __read_mostly;
static DEFINE_SPINLOCK(ekcfi_tbl_lock);

static DEFINE_PER_CPU(bool, in_ekcfi_check);

// static bool in_ekcfi_check_v2;

// nopl   0x8(%rax,%rax,1)
static const unsigned char ekcfi_nop[] = { 0x0f, 0x1f, 0x44, 0x00, 0x08 };

// Kernel text poking APIs we have to use intrusively
static void(__rcu *ekcfi_text_poke_queue)(void *, const void *, size_t,
					  const void *) __read_mostly;
static void(__rcu *ekcfi_text_poke_finish)(void) __read_mostly;
static bool(__rcu *ekcfi_within_blacklist)(unsigned long) __read_mostly;
// points to text_mutex, thus safe
static struct mutex __rcu *ekcfi_text_mutex __read_mostly;

// Support single BPF prog for now
static struct bpf_prog __rcu *ekcfi_prog1;
static struct bpf_prog __rcu *ekcfi_prog2;

// Trampoline
extern void ekcfi_tramp_64(void);
extern void ekcfi_tramp_ret_64(void);

static inline const char *ekcfi_nop_replace(void)
{
	return ekcfi_nop;
}

static inline const char *ekcfi_call_replace(unsigned long addr,
						 unsigned long target)
{
	return text_gen_insn(CALL_INSN_OPCODE, (void *)addr, (void *)target);
}

static inline void __ekcfi_make_call(unsigned long addr, unsigned long target)
{
	const char *new;
	new = ekcfi_call_replace(addr, target);

	rcu_dereference(ekcfi_text_poke_queue)((void *)addr, new,
						   EKCFI_PATCH_SIZE, NULL);
	rcu_dereference(ekcfi_text_poke_finish)();
}

static inline bool __ekcfi_within_blacklist(unsigned long addr)
{
	return rcu_dereference(ekcfi_within_blacklist)(addr);
}

static inline void __ekcfi_make_nop(unsigned long addr)
{
	const char *new;
	new = ekcfi_nop_replace();

	rcu_dereference(ekcfi_text_poke_queue)((void *)addr, new,
						   EKCFI_PATCH_SIZE, NULL);
	rcu_dereference(ekcfi_text_poke_finish)();
}

static inline void ekcfi_make_call(unsigned long addr, unsigned long target)
{
	mutex_lock(rcu_dereference(ekcfi_text_mutex));
	if(!__ekcfi_within_blacklist(addr))
		__ekcfi_make_call(addr, target);
	mutex_unlock(rcu_dereference(ekcfi_text_mutex));
}

static inline void ekcfi_make_nop(unsigned long addr)
{
	mutex_lock(rcu_dereference(ekcfi_text_mutex));
	__ekcfi_make_nop(addr);
	mutex_unlock(rcu_dereference(ekcfi_text_mutex));
}

static int ekcfi_load_tbl(u64 *addrs, u64 len, u32 index)
{
	int ret = 0;
	unsigned long flags;
	struct ekcfi_tbl *et;

	spin_lock_irqsave(&ekcfi_tbl_lock, flags);

	// At this point, prevent table from changing after init
	if (rcu_access_pointer(ekcfi_tbl[index])) {
		ret = -EPERM;
		goto out_unlock;
	}

	et = kzalloc(sizeof(*et), GFP_KERNEL);
	if (!et) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	et->ekcfi_data = vzalloc(sizeof(u64) * len);
	if (!et->ekcfi_data) {
		ret = -ENOMEM;
		goto out_vmalloc_err;
	}

	if (copy_from_user(et->ekcfi_data, addrs, sizeof(u64) * len)) {
		ret = -EFAULT;
		goto out_copy_err;
	}
	et->len = len;

	rcu_assign_pointer(ekcfi_tbl[index], et);

	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);

	return 0;

out_copy_err:
	vfree(et->ekcfi_data);
out_vmalloc_err:
	kfree(et);
out_unlock:
	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);
	return ret;
}

static int ekcfi_cmp_addr(const void *a, const void *b)
{
	u64 lhs = *(u64 *)a;
	u64 rhs = *(u64 *)b;

	if (lhs < rhs)
		return -1;
	else if (lhs > rhs)
		return 1;
	else
		return 0;
}

static int ekcfi_enable_entry(u64 addr)
{
	u64 target_addr, tramp = (unsigned long)ekcfi_tramp_64;
	u64 *search_result = NULL;
	int ret = 0;
	struct ekcfi_tbl *et0 = NULL, *et1 = NULL;

	rcu_read_lock();
	et0 = rcu_dereference(ekcfi_tbl[0]);
	et1 = rcu_dereference(ekcfi_tbl[1]);

	if (!et0 && !et1) {
		ret = -EINVAL;
		goto out;
	}

	if (!rcu_access_pointer(ekcfi_text_poke_queue) &&
		!rcu_access_pointer(ekcfi_text_poke_finish) &&
		!rcu_access_pointer(ekcfi_text_mutex) &&
		!rcu_access_pointer(ekcfi_within_blacklist)) {
		ret = -EINVAL;
		goto out;
	}

	if (et0)
		search_result = bsearch(&addr, et0->ekcfi_data, et0->len, sizeof(u64),
					ekcfi_cmp_addr);

	if (!search_result && et1) {
		search_result = bsearch(&addr, et1->ekcfi_data, et1->len, sizeof(u64),
					ekcfi_cmp_addr);
		tramp = (unsigned long)ekcfi_tramp_ret_64;
	}

	if (!search_result) {
		ret = -EINVAL;
		goto out;
	}

	target_addr = *search_result;

	ekcfi_make_call(target_addr, tramp);

out:
	rcu_read_unlock();
	return ret;
}

static int ekcfi_enable_all(void)
{
	int i;
	int ret = 0;
	struct ekcfi_tbl *et0, *et1;

	rcu_read_lock();

	et0 = rcu_dereference(ekcfi_tbl[0]);
	et1 = rcu_dereference(ekcfi_tbl[1]);

	if (!et0 && !et1) {
		ret = -EINVAL;
		goto out;
	}

	if (!rcu_access_pointer(ekcfi_text_poke_queue) &&
		!rcu_access_pointer(ekcfi_text_poke_finish) &&
		!rcu_access_pointer(ekcfi_text_mutex) &&
		!rcu_access_pointer(ekcfi_within_blacklist)) {
		ret = -EINVAL;
		goto out;
	}

	if (et0 && !et_enabled[0]) {
		for (i = 0; i < et0->len; i++) {
			ekcfi_make_call(et0->ekcfi_data[i], (unsigned long)ekcfi_tramp_64);
		}
		et_enabled[0] = true;
	}

	if (et1 && !et_enabled[1]) {
		for (i = 0; i < et1->len; i++) {
			ekcfi_make_call(et1->ekcfi_data[i], (unsigned long)ekcfi_tramp_ret_64);
		}
		et_enabled[1] = true;
	}
out:
	rcu_read_unlock();
	return ret;
}

static int ekcfi_define_sym(u64 poke_queue_addr, u64 poke_finish_addr,
				u64 text_mutex_addr, u64 within_blacklist_addr)
{
	int ret = 0;
	unsigned long flags;

	spin_lock_irqsave(&ekcfi_tbl_lock, flags);

	if (rcu_access_pointer(ekcfi_text_poke_queue) ||
		rcu_access_pointer(ekcfi_text_poke_finish) ||
		rcu_access_pointer(ekcfi_text_mutex) ||
		rcu_access_pointer(ekcfi_within_blacklist)) {
		ret = -EPERM;
		goto out_unlock;
	}

	rcu_assign_pointer(ekcfi_text_poke_queue, poke_queue_addr);
	rcu_assign_pointer(ekcfi_text_poke_finish, poke_finish_addr);
	rcu_assign_pointer(ekcfi_text_mutex, text_mutex_addr);
	rcu_assign_pointer(ekcfi_within_blacklist, within_blacklist_addr);

out_unlock:
	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);
	return ret;
}

static int ekcfi_attach_bpf(u32 prog_fd, u32 index)
{
	int ret = 0;
	unsigned long flags;
	struct bpf_prog *prog;

	spin_lock_irqsave(&ekcfi_tbl_lock, flags);

	// For now do not allow updating attached prog
	if (index == 0 && rcu_access_pointer(ekcfi_prog1)) {
		ret = -EPERM;
		goto out_unlock;
	}
	if (index == 1 && rcu_access_pointer(ekcfi_prog2)) {
		ret = -EPERM;
		goto out_unlock;
	}

	// We are going to hold this refcnt
	prog = bpf_prog_get_type_dev(prog_fd, BPF_PROG_TYPE_TRACEPOINT, false);
	if (IS_ERR(prog)) {
		ret = PTR_ERR(prog);
		goto out_unlock;
	}

	if (index == 0)
		rcu_assign_pointer(ekcfi_prog1, prog);
	else if (index == 1)
		rcu_assign_pointer(ekcfi_prog2, prog);

out_unlock:
	spin_unlock_irqrestore(&ekcfi_tbl_lock, flags);
	return ret;
}

static long ekcfi_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	union ekcfi_attr kattr = { 0 };
	union ekcfi_attr *attr = (union ekcfi_attr *)arg;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (copy_from_user(&kattr, attr, sizeof(kattr)))
		return -EFAULT;

	switch (cmd) {
	case EKCFI_LOAD_TBL:
		ret = ekcfi_load_tbl(kattr.addrs, kattr.len, kattr.tbli);
		break;

	case EKCFI_ENABLE_ENTRY:
		ret = ekcfi_enable_entry(kattr.target_addr);
		break;

	case EKCFI_ENABLE_ALL:
		ret = ekcfi_enable_all();
		break;

	case EKCFI_DEFINE_SYM:
		ret = ekcfi_define_sym(kattr.poke_queue_addr,
					   kattr.poke_finish_addr,
					   kattr.text_mutex_addr,
					   kattr.within_blacklist_addr);
		break;

	case EKCFI_ATTACH_BPF:
		ret = ekcfi_attach_bpf(kattr.prog_fd, kattr.index);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

int __nocfi noinstr ekcfi_check(u64 caller, u64 callee, u32 index)
{
	struct ekcfi_ctx ctx;
	struct bpf_prog *prog = NULL;
	unsigned ret;	

	if (!in_task() || !current->pid)
		return 0;
	/* 
	 * Workaround: potential race condition
	 * TOCTTOU
	 */	
	/*	
	if (in_ekcfi_check_v2)
		return 0;
	in_ekcfi_check_v2 = true;
	*/

	preempt_disable();

	// Prevent recursion
	if (this_cpu_read(in_ekcfi_check))
		goto out_preempt_enable;

	this_cpu_write(in_ekcfi_check, true);

	rcu_read_lock();

	// Make sure we do have a prog to run
	if (index == 0)
		prog = rcu_dereference(ekcfi_prog1);
	else if (index == 1)
		prog = rcu_dereference(ekcfi_prog2);

	if (!prog)
		goto out_unlock;

	ctx.caller = caller;
	ctx.callee = callee;

	// Call eBPF prog
	// Not need for migrate_disable -- we already have preempt_disable
	ret = prog->bpf_func(&ctx, prog->insnsi);

	// If we need to panic, we do it before clearing in_ekcfi_check to
	// prevent entering this hook again during panic
	if (unlikely(ret == EKCFI_RET_PANIC))
		panic("eKCFI failure at 0x%llx (target: 0x%llx)\n", caller, callee);

out_unlock:
	rcu_read_unlock();
	this_cpu_write(in_ekcfi_check, false);
out_preempt_enable:
	preempt_enable();
	//in_ekcfi_check_v2 = false;
	return 0;
}

// file_operations for proc-fs
static const struct proc_ops ekcfi_fops = {
	.proc_flags = PROC_ENTRY_PERMANENT,
	.proc_ioctl = ekcfi_ioctl
};

static int __init ekcfi_init(void)
{
	if (!proc_create(EKCFI_FILE_NAME, 0600, NULL, &ekcfi_fops))
		return -ENOMEM;

	return 0;
}

static void __exit ekcfi_exit(void)
{
	remove_proc_entry(EKCFI_FILE_NAME, NULL);
	// TODO: Cleanup used resources
}

// Register init and exit funtions
module_init(ekcfi_init);
module_exit(ekcfi_exit);
