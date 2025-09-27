// test_process_and_seh.c - Triggera DEBUG_010, DEBUG_040, DEBUG_041
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>

jmp_buf env;

// Handler per eccezioni
LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        printf("Breakpoint exception in vectored handler\n");
        pExceptionInfo->ContextRecord->Rip++;  // Skip breakpoint
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// Handler per segnali (alternativa a __try/__except)
void handle_sigsegv(int sig) {
    longjmp(env, 1);
}

int main() {
    printf("Testing process detection and SEH...\n");
    
    // Check for debugger process names
    const char* debuggers[] = {"ollydbg", "x64dbg", "windbg", "ida", "immunity"};
    char windowTitle[256];
    
    for (int i = 0; i < 5; i++) {
        HWND hwnd = FindWindowA(NULL, debuggers[i]);
        if (hwnd) {
            printf("Debugger window found: %s\n", debuggers[i]);
            return 1;
        }
    }
    
    // Get current process name
    char processName[MAX_PATH];
    GetModuleFileNameA(NULL, processName, MAX_PATH);
    _strlwr(processName);
    
    for (int i = 0; i < 5; i++) {
        if (strstr(processName, debuggers[i])) {
            printf("Running under debugger: %s\n", debuggers[i]);
            return 2;
        }
    }
    
    // SEH/VEH manipulation
    PVOID handler = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!handler) {
        printf("Failed to add vectored exception handler\n");
        return 3;
    }
    
    // Trigger test exception (usando setjmp/longjmp invece di __try/__except)
    signal(SIGSEGV, handle_sigsegv);
    
    if (setjmp(env) == 0) {
        // Prova ad eseguire INT3
        __asm__ volatile ("int3");  // INT3 instruction
        printf("INT3 did not trigger - debugger present\n");
        return 4;
    } else {
        printf("Exception handled by signal handler\n");
    }
    
    RemoveVectoredExceptionHandler(handler);
    
    // SetUnhandledExceptionFilter test
    SetUnhandledExceptionFilter(NULL);
    
    printf("No debugger processes detected\n");
    return 0;
}