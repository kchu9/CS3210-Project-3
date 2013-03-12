#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
 
MODULE_LICENSE("GPL");
 
#define MODULE_NAME "[sysmon] "
static int numElements=10;
static struct kprobe probe[10];
static uid_t uid;
static char *sysCalls[]={"sys_dup","sys_gettid","sys_getpid",/*"sys_dup",*/"stub_clone","sys_chmod","sys_chdir","sys_mkdir","sys_rmdir","sys_brk","sys_access"}; 
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
	     printk(KERN_INFO MODULE_NAME
                    /* sycall pid tid args.. */
                    "access call: %lu %d %d args 0x\n",
                    val, current->pid, current->tgid );
            
	    break;
	case __NR_brk:
	     printk(KERN_INFO MODULE_NAME 
                    "brk call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
            
	    break;
	case __NR_chdir:
	     printk(KERN_INFO MODULE_NAME 
                    "chdir call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
            
	    break;
	case __NR_chmod:
	     printk(KERN_INFO MODULE_NAME
                    /* sycall pid tid args.. */
                    "chmod call: %lu %d %d args 0x\n",
                    val, current->pid, current->tgid);
                    /*regs->rdi, regs->rdi, regs->rsi);*/
            break;
	case __NR_clone:
	     printk(KERN_INFO MODULE_NAME 
                    "clone call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
            
	    break;
	case __NR_getpid:
	     printk(KERN_INFO MODULE_NAME 
                    "getpid call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
            
	    break;
	case __NR_gettid:
	     printk(KERN_INFO MODULE_NAME 
                    "gettid call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_dup:
	     printk(KERN_INFO MODULE_NAME 
                    "gettid call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
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
	
   for(i=0;i<numElements;i++)
   {
   /* probe.symbol_name = "sys_mkdir"; */   
    probe[i].symbol_name = sysCalls[i];
    probe[i].pre_handler = sysmon_intercept_before; /* called prior to function */
    probe[i].post_handler = sysmon_intercept_after; /* called on function return */
	}
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
   } printk(KERN_INFO MODULE_NAME "unloaded\n");
	
}
