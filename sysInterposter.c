#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
 
MODULE_LICENSE("GPL");
 
#define MODULE_NAME "[sysmon] "
static int numElements=30;
static struct kprobe probe[30];
static uid_t uid;
static char *sysCalls[]={"sys_close","sys_execve","sys_munmap","sys_lseek","sys_getdents","sys_newlstat","sys_fcntl","sys_exit_group","sys_ioctl","sys_pipe","sys_select","sys_wait4","sys_newfstat","sys_mmap","sys_newstat","sys_read","sys_write","sys_open","stub_fork","sys_dup2","sys_dup","sys_gettid","sys_getpid","stub_clone","sys_chmod","sys_chdir","sys_mkdir","sys_rmdir","sys_brk","sys_access"}; 
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
	case __NR_close:
	     printk(KERN_INFO MODULE_NAME 
                    "close call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_execve:
	     printk(KERN_INFO MODULE_NAME 
                    "execve call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_munmap:
	     printk(KERN_INFO MODULE_NAME 
                    "munmap call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_lseek:
	     printk(KERN_INFO MODULE_NAME 
                    "lseek call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_getdents:
	     printk(KERN_INFO MODULE_NAME 
                    "getdents call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_fcntl:
	     printk(KERN_INFO MODULE_NAME 
                    "fcntl call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_exit_group:
	     printk(KERN_INFO MODULE_NAME 
                    "exit_group call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_lstat:
	     printk(KERN_INFO MODULE_NAME 
                    "lstat call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_ioctl:
	     printk(KERN_INFO MODULE_NAME 
                    "icotl call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_pipe:
	     printk(KERN_INFO MODULE_NAME 
                    "pipe call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_select:
	     printk(KERN_INFO MODULE_NAME 
                    "select call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	case __NR_wait4:
	     printk(KERN_INFO MODULE_NAME 
                    "wait4 call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
 
	case __NR_fstat:
	     printk(KERN_INFO MODULE_NAME 
                    "fstat call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	 case __NR_mmap:
	     printk(KERN_INFO MODULE_NAME 
                    "mmap call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	 case __NR_stat:
	     printk(KERN_INFO MODULE_NAME 
                    "stat call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

        case __NR_read:
	     printk(KERN_INFO MODULE_NAME 
                    "read call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

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
                    "dup call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_dup2:
	     printk(KERN_INFO MODULE_NAME 
                    "dup2 call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_fork:
	     printk(KERN_INFO MODULE_NAME 
                    "fork call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_open:
	     printk(KERN_INFO MODULE_NAME 
                    "open call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;
	case __NR_write:
	     printk(KERN_INFO MODULE_NAME 
                    "write call: %lu %d %d args 0x \n",
                    val, current->pid, current->tgid);
	    break;

	default:
            ret = 0;
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
	printk("Loading %s \n",sysCalls[i]);
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
