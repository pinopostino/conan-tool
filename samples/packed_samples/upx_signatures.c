#include <windows.h>
#include <stdio.h>

// Signature UPX rilevabili nel codice
const char upx_signature[] = "UPX!";
const char upx_info[] = "$Info: This file is packed with the UPX executable packer";

int main() {
    printf("UPX Signature Detection Sample\n");
    // Le stringhe UPX nel codice sono rilevabili dal detector
    return 0;
}