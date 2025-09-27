#include <stdio.h>
#include <string.h>    // Aggiunto per strstr e memcpy
#include <intrin.h>

void check_vm_indicators() {
    // Prefissi MAC address VM (stringhe rilevabili)
    const char* mac_prefixes[] = {
        "00:0C:29", "00:1C:14", "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "52:54:00", // QEMU
        NULL
    };
    
    // CPUID hypervisor detection
    int cpuInfo[4];
    __cpuid(cpuInfo, 0x40000000); // Hypervisor leaf
    
    // Signature detection (rilevabile)
    char signature[13] = {0};
    memcpy(signature, &cpuInfo[1], 4);
    memcpy(signature + 4, &cpuInfo[2], 4);
    memcpy(signature + 8, &cpuInfo[3], 4);
    
    // Check per signature note
    if (strstr(signature, "VMware") || strstr(signature, "VBox")) {
        printf("Trovata signature hypervisor: %s\n", signature);
    }
}

// AGGIUNGI LA FUNZIONE MAIN!
int main() {
    printf("MAC Address & CPU Detection Sample\n");
    check_vm_indicators();
    printf("Controllo completato\n");
    return 0;
}