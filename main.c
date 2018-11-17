#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ptrace.h>
#include <linux/moduleparam.h>

#ifdef CONFIG_X86_64
#define __NR_ptrace 101
#define __NR_ptrace_32 26
#else
#define __NR_ptrace 26
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Soxfmr@foxmail.com");
MODULE_DESCRIPTION("Anti Anti-ptrace");

static long *sys_call_table = NULL;
static long *ia32_sys_call_table = NULL;

static char *input_sys_call_table = "0";
static char *input_ia32_sys_call_table = "0";

module_param(input_sys_call_table, charp, 0000);
MODULE_PARM_DESC(input_sys_call_table, "Address of sys_call_table");
module_param(input_ia32_sys_call_table, charp, 0000);
MODULE_PARM_DESC(input_ia32_sys_call_table, "Address of ia32_sys_call_table");

static asmlinkage long (*old_sys_ptrace) (long request, long pid, unsigned long addr,
			   unsigned long data);

static long hooked_sys_ptrace(long request, long pid, unsigned long addr, unsigned long data)
{
    struct task_struct *task = current;

    if (request == PTRACE_TRACEME && strncmp(task->comm, "strace", sizeof("strace") - 1) != 0) {
        printk(KERN_INFO "Tampering process: %s, pid: %d\n", task->comm, task->pid);
        return 0;
    }

    return old_sys_ptrace(request, pid, addr, data);
}

static int __init ptraceme_init(void)
{
    unsigned long *old_ia32_sys_ptrace;

    write_cr0(read_cr0() & (~ 0x10000));

    if (kstrtoul(input_sys_call_table, 16, (unsigned long *) &sys_call_table) == 0 && *sys_call_table != 0) {
        old_sys_ptrace = sys_call_table[__NR_ptrace];
        sys_call_table[__NR_ptrace] = hooked_sys_ptrace;
        printk(KERN_INFO "sys_call_table located at %p, original sys_ptrace %p hooked\n", sys_call_table, old_sys_ptrace);
    }

#ifdef __NR_ptrace_32
    if (kstrtoul(input_ia32_sys_call_table, 16, (unsigned long *) &ia32_sys_call_table) == 0 && *ia32_sys_call_table != 0) {
        old_ia32_sys_ptrace = ia32_sys_call_table[__NR_ptrace_32];
        ia32_sys_call_table[__NR_ptrace_32] = hooked_sys_ptrace;
        printk(KERN_INFO "ia32_sys_call_table located at %p, original sys_ptrace %p hooked\n", ia32_sys_call_table, old_ia32_sys_ptrace);
    }
#endif

    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit ptraceme_cleanup(void)
{
    write_cr0(read_cr0() & (~ 0x10000));

    if (*sys_call_table != NULL && old_sys_ptrace != NULL) {
        sys_call_table[__NR_ptrace] = old_sys_ptrace;
        printk("Restore origin sys_ptrace: %p\n", old_sys_ptrace);
    }

#ifdef __NR_ptrace_32
    if (*ia32_sys_call_table != NULL && old_sys_ptrace != NULL) {
        ia32_sys_call_table[__NR_ptrace_32] = old_sys_ptrace;
        printk("Restore origin sys_ptrace (ia32): %p\n", old_sys_ptrace);
    }
#endif

    write_cr0(read_cr0() | 0x10000);
}

module_init(ptraceme_init);
module_exit(ptraceme_cleanup);