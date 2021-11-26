
#include <linux/init.h>
#include <linux/module.h> 
#include <linux/kernel.h>

// default configuration...
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dan0xcc");
MODULE_DESCRIPTION("hello world driver"); 
MODULE_VERSION("1.00");


// loading the driver stack on insmoding 

// __init macro: The linker inserts a corresponding kernel code in to a dedicated section so it  
// loads the driver and unloads it as needed. This section is unqiue to compiling & linking drivers. 
static int __init hellowrld_init(void) {
    printk(KERN_INFO "Hello from kernel! :)\n"); 
    return 0; 
}

// unloading the driver from the stack on rmmod
static void __exit hellowrld_exit(void) {
    printk(KERN_INFO "Bye! from kernel! :()\n"); 
} 

module_init(hellowrld_init); // invokes loading 
module_exit(hellowrld_exit); // invokes unloading 






