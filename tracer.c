// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Elena-Claudia Calcan <elena.calcan26@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include <linux/kprobes.h>
#include <linux/fs.h>

#include "tracer.h"

DEFINE_SPINLOCK(lock);

#define MAXACTIVE 64

static struct proc_dir_entry *proc_tracer;
static struct list_head head;

/*
 * Holds information about memory allocation, such as the size and address of the memory allocated.
 */
struct mem_info {
	unsigned long size;
	unsigned long addr;

	struct list_head next;
};

/*
 * Holds information about a traced process.
 */
struct tracer_record {
	pid_t pid;
	int kmalloc_calls;
	int kfree_calls;
	int sched_calls;
	int up_calls;
	int down_calls;
	int lock_calls;
	int unlock_call;
	int kmalloc_mem;
	int kfree_mem;

	struct list_head mem_infos;
	struct list_head next;
};

static int tracer_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	return 0;
}

static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q, *m, *n;
	struct mem_info *mem_info;

	switch (cmd) {

	case TRACER_ADD_PROCESS:

		/* initialize the structure for a new traced process */
		tr_record = kmalloc(sizeof(*tr_record), GFP_ATOMIC);
		if (!tr_record)
			return -ENOMEM;

		spin_lock(&lock);
		tr_record->pid = arg;
		tr_record->kmalloc_calls = 0;
		tr_record->kfree_calls = 0;
		tr_record->down_calls = 0;
		tr_record->sched_calls = 0;
		tr_record->lock_calls = 0;
		tr_record->unlock_call = 0;
		tr_record->up_calls = 0;
		tr_record->kmalloc_mem = 0;
		tr_record->kfree_mem = 0;

		INIT_LIST_HEAD(&tr_record->mem_infos);

		/* add new traced process in list */
		list_add(&tr_record->next, &head);

		spin_unlock(&lock);
		break;
	case TRACER_REMOVE_PROCESS:

		list_for_each_safe(p, q, &head) {
			tr_record = list_entry(p, struct tracer_record, next);

			if (tr_record->pid == arg) {
				spin_lock(&lock);
				/* frees memory allocate by the memory info structure*/
				list_for_each_safe(m, n, &tr_record->mem_infos) {
					mem_info = list_entry(m, struct mem_info, next);

					list_del(m);
					kfree(mem_info);
				}
				/* remove element from the list and frees the memory */
				list_del(p);
				kfree(tr_record);
				spin_unlock(&lock);
			}
		}

		break;
	default:
		break;
	}

	return 0;
}

static int proc_tracer_show(struct seq_file *m, void *v)
{
	struct list_head *p, *q;
	struct tracer_record *tr_record;

	/* display the retained information via procfs file system, in the /proc/tracer file */

	seq_puts(
		m,
		"PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\t"
			"lock\tunlock\n"
	);

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);
		seq_printf(
			m,
			"%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			tr_record->pid,
			tr_record->kmalloc_calls,
			tr_record->kfree_calls,
			tr_record->kmalloc_mem,
			tr_record->kfree_mem,
			tr_record->sched_calls,
			tr_record->up_calls,
			tr_record->down_calls,
			tr_record->lock_calls,
			tr_record->unlock_call
		);
	}

	return 0;
}

static int proc_tracer_open(struct inode *inode, struct  file *file)
{
	return single_open(file, proc_tracer_show, NULL);
}

static int kmalloc_probe_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long *size;

	/* store the size of the allocated memory */
	size = (unsigned long *)ri->data;
	*size = regs->ax;

	return 0;
}

static int kmalloc_probe_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q;
	struct mem_info *mem_info;
	unsigned long *size;
	unsigned long address;

	/* get the size of the allocated data */
	size = (unsigned long *)ri->data;

	/* get the address of the allocated memory */
	address = regs_return_value(regs);

	/* store the retrieved information in the mem_info structure variable  */
	mem_info = kmalloc(sizeof(*mem_info), GFP_ATOMIC);
	if (!mem_info)
		return -ENOMEM;

	mem_info->addr = address;
	mem_info->size = *size;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);
		if (tr_record->pid == current->pid) {
			spin_lock(&lock);
			/* update traced process data on __kmalloc calls & allocated memory */
			tr_record->kmalloc_calls++;
			tr_record->kmalloc_mem += *size;
			/* store information about the new amount of memory allocated and its address */
			list_add(&mem_info->next, &tr_record->mem_infos);
			spin_unlock(&lock);
		}
	};

	return 0;
}

static int kfree_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct mem_info *mem_info;
	struct list_head *p, *q, *t;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);
		if (tr_record->pid == current->pid) {
			tr_record->kfree_calls++;
			list_for_each(t, &tr_record->mem_infos) {
				mem_info = list_entry(t, struct mem_info, next);
				spin_lock(&lock);
				/* get the size of the freed memory from address */
				if (mem_info->addr == regs->ax)
					tr_record->kfree_mem += mem_info->size;
				spin_unlock(&lock);
			}
		}
	}

	return 0;
}

static int sched_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);

		if (tr_record->pid == current->pid)
			tr_record->sched_calls++;
	}

	return 0;
}

static int up_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);

		if (tr_record->pid == current->pid)
			tr_record->up_calls++;
	}

	return 0;
}

static int down_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);

		if (tr_record->pid == current->pid)
			tr_record->down_calls++;
	}

	return 0;
}

static int mutex_lock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);

		if (tr_record->pid == current->pid)
			tr_record->lock_calls++;
	}

	return 0;
}

static int mutex_unlock_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct tracer_record *tr_record;
	struct list_head *p, *q;

	list_for_each_safe(p, q, &head) {
		tr_record = list_entry(p, struct tracer_record, next);

		if (tr_record->pid == current->pid)
			tr_record->unlock_call++;
	}

	return 0;
}


/* Declare required kretprobe structures */
static struct kretprobe kmalloc_probe = {
	.entry_handler = kmalloc_probe_entry_handler,
	.handler = kmalloc_probe_handler,
	.kp.symbol_name = "__kmalloc",
	.maxactive = MAXACTIVE,
	.data_size = sizeof(unsigned long),
};

static struct kretprobe kfree_probe = {
	.entry_handler = kfree_handler,
	.kp.symbol_name = "kfree",
	.maxactive = MAXACTIVE,
};

static struct kretprobe sched_probe = {
	.handler = sched_handler,
	.kp.symbol_name = "schedule",
	.maxactive = MAXACTIVE,
};

static struct kretprobe up_probe = {
	.handler = up_handler,
	.kp.symbol_name = "up",
	.maxactive = MAXACTIVE,
};

static struct kretprobe down_probe = {
	.handler = down_handler,
	.kp.symbol_name = "down_interruptible",
	.maxactive = MAXACTIVE,
};

static struct kretprobe mutex_lock_probe = {
	.handler = mutex_lock_handler,
	.kp.symbol_name = "mutex_lock_nested",
	.maxactive = MAXACTIVE,
};

static struct kretprobe mutex_unlock_probe = {
	.handler = mutex_unlock_handler,
	.kp.symbol_name = "mutex_unlock",
	.maxactive = MAXACTIVE,
};

/* file operation and process property*/
static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.open = tracer_open,
	.release = tracer_release,
	.unlocked_ioctl = tracer_ioctl
};

static const struct proc_ops r_pops = {
	.proc_open		= proc_tracer_open,
	.proc_read		= seq_read,
	.proc_release	= single_release
};

/* declare miscdivice structure */
static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &tracer_fops
};

static int kretprobe_init(void)
{
	int ret;

	proc_tracer = proc_create(TRACER_DEV_NAME, 0000, NULL, &r_pops);
	if (!proc_tracer)
		return -ENOMEM;

	ret = misc_register(&tracer_dev);

	if (ret < 0)
		goto remove_proc_tracer;

	INIT_LIST_HEAD(&head);

	ret = register_kretprobe(&kmalloc_probe);

	if (ret < 0)
		goto tracer_deregister;

	ret = register_kretprobe(&kfree_probe);
	if (ret < 0)
		goto unregister_kmalloc;


	ret = register_kretprobe(&sched_probe);
	if (ret < 0)
		goto unregister_kfree;

	ret = register_kretprobe(&up_probe);
	if (ret < 0)
		goto unregister_sched;

	ret = register_kretprobe(&down_probe);
	if (ret < 0)
		goto unregister_up;

	ret = register_kretprobe(&mutex_lock_probe);
	if (ret < 0)
		goto unregister_down;

	ret = register_kretprobe(&mutex_unlock_probe);
	if (ret < 0)
		goto unregister_lock;

	return 0;

unregister_lock:
	unregister_kretprobe(&mutex_lock_probe);

unregister_down:
	unregister_kretprobe(&down_probe);

unregister_up:
	unregister_kretprobe(&up_probe);

unregister_sched:
	unregister_kretprobe(&sched_probe);

unregister_kfree:
	unregister_kretprobe(&kfree_probe);

unregister_kmalloc:
	unregister_kretprobe(&kmalloc_probe);

tracer_deregister:
	misc_deregister(&tracer_dev);

remove_proc_tracer:
	proc_remove(proc_tracer);

	return -ENOMEM;
}

static void kretprobe_exit(void)
{
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&sched_probe);
	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&mutex_lock_probe);
	unregister_kretprobe(&mutex_unlock_probe);

	proc_remove(proc_tracer);
	misc_deregister(&tracer_dev);
}

module_init(kretprobe_init);
module_exit(kretprobe_exit);


MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Elena-Claudia Calcan <elena.calcan26@gmail.com>");
MODULE_LICENSE("GPL v2");
