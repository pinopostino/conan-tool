// test_breakpoints.c - Triggera DEBUG_009, DEBUG_024, DEBUG_025, DEBUG_032
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

jmp_buf env;

// Handler per SIGSEGV (segmentation fault)
void handle_sigsegv(int sig) {
    longjmp(env, 1);
}

// Function to check for software breakpoints
int check_function_for_int3(void* func, size_t size) {
    unsigned char* bytes = (unsigned char*)func;
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] == 0xCC) {  // INT3 opcode - pattern "0xCC"
            return 1;
        }
    }
    return 0;
}

void protected_function() {
    printf("This function is protected\n");
}

int main() {
    printf("Testing breakpoint detection...\n");
    
    // Check for INT3 in our code
    if (check_function_for_int3(protected_function, 50)) {
        printf("Software breakpoint (0xCC) detected\n");
        return 1;
    }
    
    // ICEBP instruction test (usando setjmp/longjmp invece di __try/__except)
    signal(SIGSEGV, handle_sigsegv);
    
    if (setjmp(env) == 0) {
        // Prova ad eseguire ICEBP
        __asm__ volatile (".byte 0xF1");  // ICEBP - pattern "0xF1"
        printf("ICEBP did not trigger - debugger present\n");
        return 2;
    } else {
        printf("ICEBP exception caught normally\n");
    }
    
    // Memory scan for breakpoint patterns
    unsigned char suspicious[] = {0xCC, 0xCC, 0xCC};  // Pattern "\\xCC"
    unsigned char code[100];
    memcpy(code, (void*)main, sizeof(code));
    
    for (int i = 0; i < sizeof(code) - 3; i++) {
        if (memcmp(&code[i], suspicious, 3) == 0) {
            printf("Suspicious breakpoint pattern found\n");
            return 3;
        }
    }
    
    printf("No breakpoints detected\n");
    return 0;
}