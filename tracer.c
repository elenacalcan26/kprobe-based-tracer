// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Linux kernel kprobe
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

#define MAXACTIVE 32

DEFINE_SPINLOCK(lock);

static struct proc_dir_entry *proc_tracer;
static struct list_head head;

struct mem_info {
    unsigned long size;
    unsigned long addr;

    struct list_head next;
};

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

static long tracer_ioctl(struct file *file, unsigned int cmd,
                        unsigned long arg)
{
    struct tracer_record *tr_record;
    struct list_head *p, *q, *m, *n;
    struct mem_info *mi;

    switch (cmd)
    {
    case TRACER_ADD_PROCESS:

        tr_record = kmalloc(sizeof(*tr_record), GFP_ATOMIC);
        if (!tr_record) {
            return -ENOMEM;
        }

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

        list_add(&tr_record->next, &head);

        break;
    case TRACER_REMOVE_PROCESS:

        list_for_each_safe(p, q, &head) {
            tr_record = list_entry(p, struct tracer_record, next);

            if (tr_record->pid == arg) {

                list_for_each_safe(m, n, &tr_record->mem_infos) {
                    mi = list_entry(m, struct mem_info, next);

                    list_del(m);
                    kfree(mi);
                }

                list_del(p);
                kfree(tr_record);
                break;

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

    size = (unsigned long*)ri->data;
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

    size = (unsigned long*)ri->data;
    address = regs_return_value(regs);

    mem_info = kmalloc(sizeof(*mem_info), GFP_ATOMIC);
    if (!mem_info) {
        return -1;
    }

    mem_info->addr = address;
    mem_info->size = *size;

    spin_lock(&lock);

    list_for_each_safe(p, q, &head) {
        tr_record = list_entry(p, struct tracer_record, next);
        if (tr_record->pid == current->pid) {
            tr_record->kmalloc_calls++;
            tr_record->kmalloc_mem += *size;
            list_add(&mem_info->next, &tr_record->mem_infos);
        }
    };
    spin_unlock(&lock);

    return 0;
}

static int kfree_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct tracer_record *tr_record;
    struct mem_info *mi;
    struct list_head *p, *q, *t;

    spin_lock(&lock);
    list_for_each_safe(p, q, &head) {
        tr_record = list_entry(p, struct tracer_record, next);
        if (tr_record->pid == current->pid) {
            tr_record->kfree_calls++;
            list_for_each(t, &tr_record->mem_infos) {
                mi = list_entry(t, struct mem_info, next);

                if (mi->addr == regs->ax) {
                    tr_record->kfree_mem += mi->size;
                    // break;
                }
            }

        }
    }

    spin_unlock(&lock);
    return 0;
}

static int sched_handler(struct kprobe *ri, struct pt_regs *regs)
{
    struct tracer_record *tr_record;
    struct list_head *p, *q;

    list_for_each_safe(p, q, &head) {
        tr_record = list_entry(p, struct tracer_record, next);

        if (tr_record->pid == current->pid) {
            tr_record->sched_calls++;
            // break;
        }
    }

    return 0;
}

static int up_handler(struct kprobe *ri, struct pt_regs *regs)
{
    struct tracer_record *tr_record;
    struct list_head *p, *q;

    list_for_each_safe(p, q, &head) {
        tr_record = list_entry(p, struct tracer_record, next);

        if (tr_record->pid == current->pid) {
            tr_record->up_calls++;
            // break;
        }
    }

    return 0;
}

static int down_handler(struct kprobe *ri, struct pt_regs *regs)
{
    struct tracer_record *tr_record;
    struct list_head *p, *q;

    list_for_each_safe(p, q, &head) {
        tr_record = list_entry(p, struct tracer_record, next);

        if (tr_record->pid == current->pid) {
            tr_record->down_calls++;
            // break;
        }
    }

    return 0;
}

static struct kretprobe kmalloc_probe = {
   .entry_handler = kmalloc_probe_entry_handler, /* entry handler */
   .handler = kmalloc_probe_handler, /* return probe handler */
   .kp.symbol_name = "__kmalloc",
   .maxactive = MAXACTIVE,
   .data_size = sizeof(unsigned long),
};

static struct kretprobe kfree_probe = {
    .entry_handler = kfree_handler,
    .kp.symbol_name = "kfree",
    .maxactive = MAXACTIVE,
};

static struct kprobe sched_probe = {
    .pre_handler = sched_handler,
    .symbol_name = "schedule",
};

static struct kprobe up_probe = {
    .pre_handler = up_handler,
    .symbol_name = "up",
};

static struct kprobe down_probe = {
    .pre_handler = down_handler,
    .symbol_name = "down_interruptible",
};

static const struct file_operations tracer_fops = {
    .owner = THIS_MODULE,
    .open = tracer_open,
    .release = tracer_release,
    .unlocked_ioctl = tracer_ioctl
};

static struct miscdevice tracer_dev = {
    .minor = TRACER_DEV_MINOR,
    .name = TRACER_DEV_NAME,
    .fops = &tracer_fops
};

static const struct proc_ops r_pops = {
	.proc_open		= proc_tracer_open,
	.proc_read		= seq_read,
	.proc_release	= single_release
};

static int kretprobe_init(void)
{
    int ret;

    proc_tracer = proc_create(TRACER_DEV_NAME, 0000, NULL, &r_pops);
    if (!proc_tracer) {
        return -ENOMEM;
    }

    ret = misc_register(&tracer_dev);

    if (ret < 0) {
        proc_remove(proc_tracer);
        return -ENOMEM;
    }

    INIT_LIST_HEAD(&head);

    ret = register_kretprobe(&kmalloc_probe);

    if (ret < 0) {
        return -ENOMEM;
    }

    ret = register_kretprobe(&kfree_probe);

    ret = register_kprobe(&sched_probe);

    ret = register_kprobe(&up_probe);

    ret = register_kprobe(&down_probe);

    return 0;
}

static void kretprobe_exit(void)
{
    unregister_kretprobe(&kmalloc_probe);
    unregister_kretprobe(&kfree_probe);
    unregister_kprobe(&sched_probe);
    unregister_kprobe(&up_probe);
    unregister_kprobe(&down_probe);

    proc_remove(proc_tracer);
    misc_deregister(&tracer_dev);
}

module_init(kretprobe_init);
module_exit(kretprobe_exit);


MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Elena-Claudia Calcan <elena.calcan26@gmail.com>");
MODULE_LICENSE("GPL v2");
