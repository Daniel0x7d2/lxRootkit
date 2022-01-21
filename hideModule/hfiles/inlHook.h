#pragma once

#include "pch.h"
#include "utils64.h" 

#define ORIGINAL_PATTERN_SZ 16
struct inlHook 
{
    unsigned long targetFunc;   /* target function */
    unsigned long myFunc;       /* our hook */
    unsigned long *trampAddress; 
    
    unsigned char* originalPattern; 
    unsigned char* oldPattern;
    size_t _szMov; 
    size_t _szJmp; 

}; 
static struct inlHook hook;

/* mov rax, [addr] pattern */ 
static unsigned char movPattern[] = { 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00 };  
/* jmp rax pattern */ 
static unsigned char jmpPattern[] = { 0xFF, 0xE0, 0xC3 }; 

void tramp(void)
{    
    /* -1 for the ret */
    asm volatile("jmp *%0" : : "r" (hook.targetFunc + (hook._szMov + hook._szJmp) - 1));   
}

void exec_page(unsigned long original_address)
{
    unsigned char* execuable_page = NULL; 

    execuable_page = module_alloc(PAGE_SIZE); 
    if(execuable_page == NULL) {
        printk(KERN_INFO "[-] module_alloc failed!");
        return;
    }

    *(unsigned long*)&movPattern[3] = (unsigned long)execuable_page;
    memcpy_s(execuable_page, PAGE_SIZE, hook.oldPattern, sizeof(hook.oldPattern));
    memcpy_s(execuable_page + PAGE_SIZE, hook._szMov, movPattern, hook._szMov);
    memcpy_s(execuable_page + hook._szMov, hook._szJmp, jmpPattern, hook._szJmp); 

    // save the address for jumping
    hi.trampAddress = (unsigned long)execuable_page;
}  

void inline_hook_x64(unsigned long toHook, unsigned long theHook, unsigned char old[])
{
    hook.myFunc = (unsigned long)theHook; 
    hook.targetFunc = toHook; 
    hook.oldPattern = old; 


    // we can replace 'theHook' with hi.trampAddress.after exec_page will execute 
    *(unsigned long*)&movPattern[3] = (unsigned long)theHook;
   
    size_t szMovPattern = sizeof(movPattern); 
    size_t szJmpPattern = sizeof(jmpPattern); 
    
    hook._szMov = szMovPattern; 
    hook._szJmp = szJmpPattern; 

    wpOFF(); 
    memcpy((unsigned long)(toHook), movPattern, szMovPattern);
    memcpy((unsigned long)(toHook + szMovPattern), jmpPattern, szJmpPattern);
    wpON();
}

void inline_unhook_x64()
{

    memcpy((unsigned long)(hook.originalPattern), hook.oldPattern, sizeof(hook.oldPattern)); 

    wpOFF(); 
    memcpy(hook.targetFunc, hook.originalPattern, sizeof(hook.originalPattern)); 
    wpON(); 
}
