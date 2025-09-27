#include <windows.h>
#include <stdio.h>

void check_virtualbox_files() {
    // Cerca file specifici VirtualBox
    const char* vbox_files[] = {
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
        "C:\\windows\\system32\\drivers\\VBoxGuest.sys",
        "C:\\windows\\system32\\VBoxService.exe",
        NULL
    };
    
    for (int i = 0; vbox_files[i] != NULL; i++) {
        if (GetFileAttributesA(vbox_files[i]) != INVALID_FILE_ATTRIBUTES) {
            printf("Trovato file VirtualBox: %s\n", vbox_files[i]);
        }
    }
}

// AGGIUNGI LA FUNZIONE MAIN!
int main() {
    printf("VirtualBox File Detection Sample\n");
    check_virtualbox_files();
    printf("Controllo completato\n");
    return 0;
}