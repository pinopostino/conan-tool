// test_timing.c - Triggera DEBUG_003, DEBUG_021, DEBUG_022, DEBUG_030
#include <windows.h>
#include <intrin.h>
#include <stdio.h>

int main() {
    printf("Testing timing anti-debug...\n");
    
    // RDTSC timing check
    unsigned __int64 t1 = __rdtsc();  // First rdtsc
    Sleep(10);  
    unsigned __int64 t2 = __rdtsc();  // Second rdtsc - pattern matches
    
    if ((t2 - t1) > 100000000) {
        printf("RDTSC timing anomaly detected\n");
        return 1;
    }
    
    // GetTickCount timing
    DWORD tick1 = GetTickCount();
    Sleep(100);
    DWORD tick2 = GetTickCount();
    
    if ((tick2 - tick1) > 500) {
        printf("GetTickCount timing anomaly\n");
        return 2;
    }
    
    // QueryPerformanceCounter check
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(10);
    QueryPerformanceCounter(&end);
    
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (elapsed > 0.5) {
        printf("Performance counter anomaly\n");
        return 3;
    }
    
    printf("No timing anomalies\n");
    return 0;
}