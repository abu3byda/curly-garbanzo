#include "anticheat.h"

bool IsAntiCheatRunning() {
    // قائمة بأسماء الأجهزة اللي بيفتحها برامج الحماية (زي ما هو في جيدرا)
    LPCWSTR Devices[] = {
        L"NvAdminDevice", // EAC
        L"NvAPI",         // EAC
        L"NvMllDdk",      // EAC
        L"nvml",          // EAC
        L"clipc",         // BattleEye
        L"Nal",           // بعض الحمايات التانية
        L"Valorant"
    };

    for (int i = 0; i < sizeof(Devices) / sizeof(LPCWSTR); i++) {
        WCHAR szPath[128];
        wsprintfW(szPath, L"\\\\.\\%s", Devices[i]);
        HANDLE hTest = CreateFileW(szPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hTest != INVALID_HANDLE_VALUE) {
            CloseHandle(hTest);
            return true; // تم العثور على حماية
        }
    }
    return false;
}