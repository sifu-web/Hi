#include "kpatch.h"
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/pid.h>
#include <linux/mm.h>

KPM_NAME("rt_kpm");
KPM_VERSION("1.0");
KPM_LICENSE("GPL");
KPM_AUTHOR("sifu-web");
KPM_DESCRIPTION("Hardware Level AC Bypass Driver");

#define DEVICE_NAME "rt_kpm"
#define RT_MAGIC    'R'

struct rw_req {
    pid_t pid;
    uintptr_t addr;
    void *buf;
    size_t size;
};

#define IOCTL_READ  _IOWR(RT_MAGIC, 1, struct rw_req)
#define IOCTL_WRITE _IOWR(RT_MAGIC, 2, struct rw_req)

static int (*apv_fn)(struct task_struct *, unsigned long, void *, int, unsigned int);
static struct pid *(*find_pid_fn)(int);
static struct task_struct *(*get_pid_task_fn)(struct pid *, enum pid_type);
static void (*put_pid_fn)(struct pid *);
static struct mm_struct *(*get_mm_fn)(struct task_struct *);
static void (*put_mm_fn)(struct mm_struct *);
static void (*put_task_fn)(struct task_struct *);
static void *(*kzalloc_fn)(size_t, gfp_t);
static void (*kfree_fn)(const void *);

static long rt_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct rw_req req;
    if (copy_from_user(&req, (void __user *)arg, sizeof(req))) return -EFAULT;

    struct pid *pid_struct = find_pid_fn(req.pid);
    if (!pid_struct) return -ESRCH;
    struct task_struct *task = get_pid_task_fn(pid_struct, PIDTYPE_PID);
    put_pid_fn(pid_struct);
    if (!task) return -ESRCH;

    struct mm_struct *mm = get_mm_fn(task);
    if (!mm) { put_task_fn(task); return -EINVAL; }

    void *kern_buf = kzalloc_fn(req.size, GFP_KERNEL);
    if (!kern_buf) { put_mm_fn(mm); put_task_fn(task); return -ENOMEM; }

    if (cmd == IOCTL_READ) {
        if (apv_fn(task, req.addr, kern_buf, req.size, 0) == req.size)
            copy_to_user(req.buf, kern_buf, req.size);
        else req.size = 0;
    } else if (cmd == IOCTL_WRITE) {
        if (copy_from_user(kern_buf, req.buf, req.size) == 0)
            apv_fn(task, req.addr, kern_buf, req.size, FOLL_WRITE);
        else req.size = 0;
    }

    kfree_fn(kern_buf);
    put_mm_fn(mm);
    put_task_fn(task);
    copy_to_user((void __user *)arg, &req, sizeof(req));
    return 0;
}

static const struct file_operations rt_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = rt_ioctl,
};

static struct miscdevice rt_misc = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &rt_fops,
    .mode = 0666,
};

int __init kpm_init(const char *args, const char *event, void *__user reserved) {
    apv_fn = (void *)kp_get_symbol("access_process_vm", 0);
    find_pid_fn = (void *)kp_get_symbol("find_get_pid", 0);
    get_pid_task_fn = (void *)kp_get_symbol("get_pid_task", 0);
    put_pid_fn = (void *)kp_get_symbol("put_pid", 0);
    get_mm_fn = (void *)kp_get_symbol("get_task_mm", 0);
    put_mm_fn = (void *)kp_get_symbol("mmput", 0);
    put_task_fn = (void *)kp_get_symbol("put_task_struct", 0);
    kzalloc_fn = (void *)kp_get_symbol("kzalloc", 0);
    kfree_fn = (void *)kp_get_symbol("kfree", 0);

    int (*misc_reg)(struct miscdevice *) = (void *)kp_get_symbol("misc_register", 0);
    
    if (!apv_fn || !misc_reg || !find_pid_fn || !get_pid_task_fn) return -1;
    misc_reg(&rt_misc);
    pr_info("rt_kpm: Loaded Successfully\n");
    return 0;
}

void __exit kpm_exit(void *__user reserved) {
    void (*misc_dereg)(struct miscdevice *) = (void *)kp_get_symbol("misc_deregister", 0);
    if (misc_dereg) misc_dereg(&rt_misc);
    pr_info("rt_kpm: Unloaded\n");
}
