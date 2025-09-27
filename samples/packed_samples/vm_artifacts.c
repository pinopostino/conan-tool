#include <windows.h>
#include <stdio.h>

// Stringhe di protector VM rilevabili
const char* vm_protectors[] = {
    "Themida",
    "WinLicense", 
    "VMProtect",
    "Obsidium",
    "Enigma",
    NULL
};

int main() {
    printf("VM Protection Artifacts Sample\n");
    // Le stringhe dei protector nel codice sono rilevabili
    return 0;
}