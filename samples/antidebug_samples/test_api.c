// test_api_detection.c - Triggera DEBUG_001, DEBUG_002, DEBUG_018, DEBUG_020
#include <windows.h>
#include <stdio.h>

int main() {
    printf("Testing API-based anti-debug...\n");
    
    // API 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        printf("Debugger detected via IsDebuggerPresent\n");
        return 1;
    }
    
    // API 2: CheckRemoteDebuggerPresent
    BOOL remoteDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDbg);
    if (remoteDbg) {
        printf("Remote debugger detected\n");
        return 2;
    }
    
    // API 3: OutputDebugStringA trick
    SetLastError(0);
    OutputDebugStringA("Anti-Debug Test");
    if (GetLastError() == 0) {
        printf("Debugger detected via OutputDebugString\n");
        return 3;
    }
    
    // API 4: GetThreadContext for hardware breakpoints
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    GetThreadContext(GetCurrentThread(), &ctx);
    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
        printf("Hardware breakpoints detected\n");
        return 4;
    }
    
    printf("No debugger detected\n");
    return 0;
}