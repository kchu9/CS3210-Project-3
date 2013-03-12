#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
 
MODULE_LICENSE("GPL");
 
#define MODULE_NAME "[sysmon] "
static int numElements=2;
static struct kprobe probe[2];
static uid_t uid;
static char *sysCalls[]={"sys_mkdir","sys_rmdir"}; 
/* pt_regs defined in include/asm-x86/ptrace.h
 *
 * For information associating registers with function arguments, see:
 * http://lxr.linux.no/linux+v2.6.24.6/arch/x86/kernel/entry_64.S#L182
 */
static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{

    int ret = 0;
    long val=regs->rax;
    if (current->uid != uid)
        return 0;	
    switch (val) {
        case __NR_mkdir:
            printk(KERN_INFO MODULE_NAME
                    /* sycall pid tid args.. */
                    "mkdir call: %lu %d %d args 0x%lu '%s' %d\n",
                    val, current->pid, current->tgid,
                    (uintptr_t)regs->rdi, (char*)regs->rdi, (int)regs->rsi);
            break;
        case __NR_rmdir:
            printk(KERN_INFO MODULE_NAME
                    "rmdir call: %lu %d %d args\n",
                    regs->rax, current->pid, current->tgid);
            break;
	case __NR_access:
	    printk(KERN_INFO MODULE_NAME "access call:  args 0x");
	    break;
	default:
            ret = 100;
            break;
    }
    return ret;
}
 
static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs,
        unsigned long flags)
{
    /* Here you could capture the return code if you wanted. */
   /* printk("intercept successful");*/
}
 
int init_module(void)
{
    int i;	
    uid=282853;
	printk(KERN_INFO MODULE_NAME "%s",sysCalls[0]);
   /* probe.symbol_name = "sys_mkdir"; */   
    probe[0].symbol_name = sysCalls[0];
    probe[0].pre_handler = sysmon_intercept_before; /* called prior to function */
    probe[0].post_handler = sysmon_intercept_after; /* called on function return */
	for(i=0;i<numElements;i++)
	{
 	 if (register_kprobe(&probe[i])) {
       	 printk(KERN_ERR MODULE_NAME "register_kprobe failed\n");
       	 return -EFAULT;
    	}
	}
    printk(KERN_INFO MODULE_NAME "loaded\n");
    return 0;
}
 
void cleanup_module(void)
{
    int i=0;
   for(i=0;i<numElements;i++)
  {
    unregister_kprobe(&probe[i]);
    printk(KERN_INFO MODULE_NAME "unloaded\n");
	}
}
