// test_peb_checks.c - Versione corretta per GCC
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Testing PEB anti-debug...\n");
    
    BOOL debugged = FALSE;
    DWORD ntGlobalFlag = 0;
    DWORD peb_addr = 0;
    
    // PEB BeingDebugged check - pattern "fs:[0x30]"
    __asm__ volatile (
        "mov %%fs:0x30, %%eax\n\t"
        "movzbl 0x2(%%eax), %%ebx\n\t"
        : "=b" (debugged)
        : 
        : "eax", "memory"
    );
    
    if (debugged) {
        printf("PEB.BeingDebugged = TRUE\n");
        return 1;
    }
    
    // NtGlobalFlag check
    __asm__ volatile (
        "mov %%fs:0x30, %%eax\n\t"
        "mov 0x68(%%eax), %%ecx\n\t"
        : "=c" (ntGlobalFlag)
        : 
        : "eax", "memory"
    );
    
    if (ntGlobalFlag & 0x70) {
        printf("NtGlobalFlag indicates debugging: 0x%X\n", ntGlobalFlag);
        return 2;
    }
    
    // Versione alternativa usando assembly invece di __readfsdword
    __asm__ volatile (
        "mov %%fs:0x30, %0\n\t"
        : "=r" (peb_addr)
        :
        : "memory"
    );
    
    BOOL being_debugged = *((BYTE*)peb_addr + 2);
    if (being_debugged) {
        printf("Debugger detected via PEB access\n");
        return 3;
    }
    
    printf("No debugger detected via PEB\n");
    return 0;
}