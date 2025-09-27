#include <windows.h>
#include <stdio.h>

void check_vmware_registry() {
    // Controlla chiavi registro VMware specifiche
    const char* vmware_keys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "SYSTEM\\ControlSet001\\Services\\vmci",
        "SYSTEM\\ControlSet001\\Services\\vmhgfs",
        NULL
    };
    
    for (int i = 0; vmware_keys[i] != NULL; i++) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, vmware_keys[i], 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            printf("Trovata chiave VMware: %s\n", vmware_keys[i]);
            RegCloseKey(hKey);
        }
    }
}

// AGGIUNGI QUESTA FUNZIONE MAIN!
int main() {
    printf("Controllo registry VMware...\n");
    check_vmware_registry();
    printf("Controllo completato.\n");
    return 0;
}