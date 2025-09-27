#include <windows.h>
#include <setupapi.h>
#include <stdio.h>

#pragma comment(lib, "setupapi.lib")

int main() {
    printf("Avvio hardware fingerprinting...\n");
    
    // API SetupDi per hardware enumeration (rilevabile)
    HDEVINFO hDevInfo = SetupDiGetClassDevsA(NULL, NULL, NULL, 
        DIGCF_ALLCLASSES | DIGCF_PRESENT);
    
    if (hDevInfo != INVALID_HANDLE_VALUE) {
        SP_DEVINFO_DATA DeviceInfoData;
        DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
        
        // Enumera dispositivi (rilevabile)
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++) {
            CHAR buffer[256];
            DWORD size = sizeof(buffer);
            
            // Get device properties (rilevabile)
            if (SetupDiGetDeviceRegistryPropertyA(hDevInfo, &DeviceInfoData, 
                SPDRP_DEVICEDESC, NULL, (PBYTE)buffer, sizeof(buffer), &size)) {
                
                // Cerca stringhe hardware sospette
                if (strstr(buffer, "vmware") || strstr(buffer, "virtual")) {
                    printf("Hardware sospetto: %s\n", buffer);
                }
            }
        }
        
        SetupDiDestroyDeviceInfoList(hDevInfo);
    }
    
    printf("Hardware fingerprinting completato.\n");
    return 0;
}