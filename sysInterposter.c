#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
 
#define MODULE_NAME "[sysmon] "

#define MODULE_NAME		"[socketModule] "
#define LOG_SIZE		PAGE_SIZE
#define MESSAGE_SIZE	1024
static struct proc_dir_entry *proc_entry;
static char *log_buffer;

 struct systemCallNode{
double pid;
double tgid;
struct pt_regs regs;
struct list_head list; /*kernel list structur*/
};
static spinlock_t mr_lock=SPIN_LOCK_UNLOCKED;
static int systemCallListSize;
struct  systemCallNode sysCallList; 
static int numElements=30;
static struct kprobe probe[30];
static uid_t uid;
static char *sysCalls[]={"sys_mkdir","sys_rmdir","sys_close","sys_execve","sys_munmap","sys_lseek","sys_getdents","sys_newlstat","sys_fcntl","sys_exit_group","sys_ioctl","sys_pipe","sys_select","sys_wait4","sys_newfstat","sys_mmap","sys_newstat","sys_read","sys_write","sys_open","stub_fork","sys_dup2","sys_dup","sys_gettid","sys_getpid","stub_clone","sys_chmod","sys_chdir","sys_brk","sys_access"}; 





/* pt_regs defined in include/asm-x86/ptrace.h
 *
 * For information associating registers with function arguments, see:
 * http://lxr.linux.no/linux+v2.6.24.6/arch/x86/kernel/entry_64.S#L182
 */
static int sysmon_intercept_before(struct kprobe *kp, struct pt_regs *regs)
{
struct list_head *entry;
    struct systemCallNode *aNewNode, *aNode,*temp;/*,*aNode;*/
    int ret = 0; 
    
/*	printk("SysCall: %lu PID: %d TGID: %d ARG0: %lu ARG1: %lu ARG2: %lu ARG3 %lu ARG4 %lu ARG5 %lu",regs->rax,current->pid,current->tgid,regs->rdi,regs->rsi,regs->rdx,regs->r10,regs->r8,regs->r9,temp);

	printk("size of node: %lu",sizeof("SysCall:  PID:  TGID:  ARG0:  ARG1:  ARG2:  ARG3:  ARG4:  ARG5:  \n")+2*sizeof(double)+7*sizeof(long));
*/    
     if (current->uid != uid)
    	{
	 return 0;
	}
	spin_lock_irq(&mr_lock);	
	/*create new node*/
	aNewNode=kmalloc(sizeof(*aNewNode),GFP_KERNEL);
	aNewNode->pid=current->pid;
	aNewNode->tgid=current->tgid;
	aNewNode->regs=*regs;
	INIT_LIST_HEAD(&aNewNode->list);	
	
    		/*add to list*/
	if(systemCallListSize <5)
	{

	list_add_tail(&aNewNode->list,&sysCallList.list);
	systemCallListSize++;
	}
	else
	{

	/*delete from head attempt*/
	entry=(&sysCallList.list)->next;/*->prev to remove tail*/
	temp=list_entry(entry,struct systemCallNode,list);
//	printk("Head Node Entry: %lu  ",temp->regs.rax);
	list_del_init(&temp->list);	
	kfree(temp);
	list_add_tail(&aNewNode->list,&sysCallList.list);
	}
	/*print list*/
	printk("List: ");
	list_for_each_entry(aNode,&(sysCallList.list),list){
	printk("SysNumber:%lu ->",(aNode->regs).rax);
	}
	printk("Latest Syscall Number: %lu ",regs->rax);	
	printk("\n");
	spin_unlock_irq(&mr_lock);



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
/*initialize linked list*/
    int i;	
    uid=282853;
    systemCallListSize=0;
	INIT_LIST_HEAD(&sysCallList.list);	


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
  struct systemCallNode *aNode,*tmp;
  list_for_each_entry_safe(aNode,tmp,&sysCallList.list,list){
	printk(KERN_INFO "freeing node with Sys: %lu\n",aNode->regs.rax);
	list_del(&aNode->list);
	kfree(aNode);
}	
   for(i=0;i<numElements;i++)
  {
    unregister_kprobe(&probe[i]);
   } printk(KERN_INFO MODULE_NAME "unloaded\n");
	
}
