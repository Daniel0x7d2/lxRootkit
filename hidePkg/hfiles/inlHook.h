#pragma once

#include "pch.h"
#include "utils64.h" 

#include <linux/vmalloc.h>
#define SET_PTRN_SIZE(sz) (sz > 0) ? sizeof(sz): 0 
struct inlHook 
{
    unsigned long targetFunc;   /* target function */
    unsigned long myFunc;       /* our hook */
    unsigned long trampAddr; 

    size_t _szMov; 
    size_t _szJmp; 
        
}; 
static struct inlHook hook;

/* mov rax, [addr] pattern */ 
static unsigned char movPattern[] = { 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00 };  
/* jmp rax pattern */ 
static unsigned char jmpPattern[] = { 0xFF, 0xE0, 0xC3}; 

static unsigned char t_movPattern[] = { 0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00 };  

unsigned char old[] = { 0x0F, 0x1F, 0x04, 0x00, 0x41, 0x55, 0x41, 0x54, 0x55, 0x53, 0x48, 0x89, 0xF3 };

void inline_hook_x64(unsigned long toHook, unsigned long theHook)
{
      
    hook.myFunc = (unsigned long)theHook;  
    hook.targetFunc = toHook; 
    
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

void inline_unhook_x64(void)
{
    wpOFF(); 
    memcpy((unsigned long)(hook.targetFunc), old, sizeof(old)); 
    wpON(); 
}