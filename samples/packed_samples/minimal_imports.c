#include <windows.h>
#include <stdio.h>

// API minimali tipiche dei packer
void minimal_imports() {
    HMODULE kernel32 = LoadLibraryA("kernel32.dll");
    if (kernel32) {
        FARPROC loadlib = GetProcAddress(kernel32, "LoadLibraryA");
        FARPROC getproc = GetProcAddress(kernel32, "GetProcAddress");
        FARPROC virtalloc = GetProcAddress(kernel32, "VirtualAlloc");
        
        // Pattern di dynamic loading rilevabile
    }
}

int main() {
    printf("Minimal Import Table Sample\n");
    minimal_imports();
    return 0;
}