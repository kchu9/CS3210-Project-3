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
#define LOG_SIZE		PAGE_SIZE
#define MESSAGE_SIZE	1024
#define PACKET_END "TTTTT"
struct systemCallNode{
	double pid;
	double tgid;
	struct pt_regs regs;
	struct list_head list; /*kernel list structure*/
};

static spinlock_t mr_lock=SPIN_LOCK_UNLOCKED;
static int systemCallListSize;
struct  systemCallNode sysCallList; 
static int numElements=1;
static struct kprobe probe[30];
static uid_t uid;
static char *sysCalls[]={"sys_mkdir","sys_rmdir","sys_close","sys_execve","sys_munmap",
"sys_lseek","sys_getdents","sys_newlstat","sys_fcntl","sys_exit_group",
"sys_ioctl","sys_pipe","sys_select","sys_wait4","sys_newfstat","sys_mmap",
"sys_newstat","sys_read","sys_write","sys_open","stub_fork","sys_dup2",
"sys_dup","sys_gettid","sys_getpid","stub_clone","sys_chmod","sys_chdir",
"sys_brk","sys_access"}; 


static struct proc_dir_entry *proc_uid;
static struct proc_dir_entry *proc_toggle;
static struct proc_dir_entry *proc_log;
static char *log_buffer;
static char *toggle_buffer;
static char *uid_buffer;
static int toggle;


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
     if (current->uid != uid){
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
	if(systemCallListSize <5){
		list_add_tail(&aNewNode->list,&sysCallList.list);
		systemCallListSize++;
	}
	else{

	/*delete from head attempt*/
	entry=(&sysCallList.list)->next;/*->prev to remove tail*/
	temp=list_entry(entry,struct systemCallNode,list);
//	printk("Head Node Entry: %lu  ",temp->regs.rax);
	list_del_init(&temp->list);	
	kfree(temp);
	list_add_tail(&aNewNode->list,&sysCallList.list);
	}
	/*print list*/
/*	printk("List: ");
	list_for_each_entry(aNode,&(sysCallList.list),list){
	printk("SysNumber:%lu ->",(aNode->regs).rax);
	}
	printk("Latest Syscall Number: %lu ",regs->rax);	
	printk("\n");*/
	spin_unlock_irq(&mr_lock);



    return ret;
}
 
static void sysmon_intercept_after(struct kprobe *kp, struct pt_regs *regs,
        unsigned long flags)
{
    /* Here you could capture the return code if you wanted. */
   /* printk("intercept successful");*/
}

int uid_read(char *page, char **start, off_t offset, int count, int *eof, void *data) {
	int length;

	if (offset > 0) {
		*eof = 1;
		return 0;
	}
	length = sprintf(page, "%d\n", (int) uid);
	return length;
}

ssize_t uid_write(struct file *filp, const char __user *buffer, unsigned long len, void *data) {
	char temp[10];
	if(copy_from_user(temp, buffer, len))
		return -EFAULT;

	((char*)temp)[len] = '\0';

	sscanf((const char*)temp, "%d", &uid);

	return len;
}

int toggle_read(char *page, char **start, off_t offset, int count, int *eof, void *data) {
	int length;

	if (offset > 0) {
		*eof = 1;
		return 0;
	}
	length = sprintf(page, "%d\n", (int) toggle);
	return length;
}

ssize_t toggle_write(struct file *filp, const char __user *buffer, unsigned long len, void *data) {
	char temp[10];

	if(copy_from_user(temp, buffer, len))
		return -EFAULT;

	((char*)temp)[len] = '\0';

	sscanf((const char*)temp, "%d", &toggle);

	return len;
}

int log_read(char *page, char **start, off_t offset, int count, int *eof, void *data) {
	int len;
	struct list_head *entry;
    	struct systemCallNode *temp;
	char *tempString;
	

	entry=(&sysCallList.list)->next;
	temp=list_entry(entry, struct systemCallNode,list);
	sprintf(tempString,"B.SysCall %lu \n",(temp->regs).rax);		
	strcat(log_buffer,tempString);
	strcat(log_buffer,PACKET_END);
	len = sprintf(page, "%s\n", log_buffer);

	return len;
}

ssize_t log_write(struct file *filp, const char __user *buffer, unsigned long len, void *data) {
	return 0;
}

int init_sys_monitor(void) {
/*initialize linked list*/
    int i;
	int ret = 0;
    uid=282853;
	toggle = 1;
    systemCallListSize=0;
	INIT_LIST_HEAD(&sysCallList.list);	


   for(i=0;i<numElements;i++) {
   /* probe.symbol_name = "sys_mkdir"; */   
    probe[i].symbol_name = sysCalls[i];
    probe[i].pre_handler = sysmon_intercept_before; /* called prior to function */
    probe[i].post_handler = sysmon_intercept_after; /* called on function return */
	printk("Loading %s \n",sysCalls[i]);
	}
	for(i=0;i<numElements;i++) {
 	 	if (register_kprobe(&probe[i])) {
       		printk(KERN_ERR MODULE_NAME "register_kprobe failed\n");
       		return -EFAULT;
    	}
	}

	//ProcFS
	uid_buffer = (char *) vmalloc(LOG_SIZE);
	toggle_buffer = (char *) vmalloc(MESSAGE_SIZE);
	log_buffer = (char *) vmalloc(MESSAGE_SIZE);

	if(!log_buffer || !toggle_buffer || !log_buffer) 
		ret = -ENOMEM;
	else {
		memset(uid_buffer, 0, MESSAGE_SIZE);
		memset(toggle_buffer, 0, MESSAGE_SIZE);
		memset(log_buffer, 0, LOG_SIZE);

		proc_uid = create_proc_entry("sysmon_uid", 0600, NULL);
		proc_toggle = create_proc_entry("sysmon_toggle", 0600, NULL);
		proc_log = create_proc_entry("sysmon_log", 0400, NULL);

		if(proc_uid == NULL || proc_toggle == NULL || proc_log == NULL) {
			ret = -ENOMEM;
			vfree(log_buffer);
			vfree(toggle_buffer);
			vfree(uid_buffer);
			printk(KERN_INFO MODULE_NAME "Could not create proc entry\n");
		}
		else {
			proc_uid->read_proc = uid_read;
			proc_uid->write_proc = uid_write;
			proc_toggle->read_proc = toggle_read;
			proc_toggle->write_proc = toggle_write;
			proc_log->read_proc = log_read;
			proc_log->write_proc = log_write;
			printk(KERN_INFO MODULE_NAME "Loaded Module.\n");
		}
	}

    printk(KERN_INFO MODULE_NAME "loaded\n");
    return 0;
}
 
void cleanup_sys_monitor(void) {
    int i=0;
	struct systemCallNode *aNode,*tmp;
	list_for_each_entry_safe(aNode,tmp,&sysCallList.list,list){
	printk(KERN_INFO "freeing node with Sys: %lu\n",aNode->regs.rax);
	list_del(&aNode->list);
	kfree(aNode);
}	
	for(i=0;i<numElements;i++) {
		unregister_kprobe(&probe[i]);
	}

	remove_proc_entry("sysmon_uid", NULL);
	remove_proc_entry("sysmon_toggle", NULL);
	remove_proc_entry("sysmon_log", NULL);
	vfree(toggle_buffer);
	vfree(uid_buffer);
	vfree(log_buffer);

	printk(KERN_INFO MODULE_NAME "unloaded\n");
}

module_init(init_sys_monitor);
module_exit(cleanup_sys_monitor);
