#include <windows.h>
#include <stdio.h>

// Nomi sezioni sospetti rilevabili
const char* suspicious_sections[] = {
    ".upx0",
    ".packed", 
    ".themida",
    ".vmp0",
    ".enigma1",
    NULL
};

int main() {
    printf("Suspicious Section Names Sample\n");
    // I nomi di sezione nel codice sono rilevabili
    return 0;
}
