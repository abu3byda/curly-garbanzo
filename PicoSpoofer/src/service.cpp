#include "service.h"
#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

// نوع الدوال اللي هنستدعيها
typedef NTSTATUS(NTAPI* pNtLoadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* pNtUnloadDriver)(PUNICODE_STRING DriverServiceName);
typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

bool LoadDriverAsService(LPCWSTR ServiceName, LPCWSTR DriverPath) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    // 1. رفع الصلاحية (SeLoadDriverPrivilege)
    pRtlAdjustPrivilege RtlAdjustPrivilege = (pRtlAdjustPrivilege)GetProcAddress(hNtdll, "RtlAdjustPrivilege");
    BOOLEAN bEnabled = FALSE;
    if (RtlAdjustPrivilege) {
        RtlAdjustPrivilege(10, TRUE, FALSE, &bEnabled); // 10 = SE_LOAD_DRIVER_PRIVILEGE
    }

    // 2. كتابة الـ Registry (Service Key)
    HKEY hKey;
    WCHAR szKey[512];
    wsprintfW(szKey, L"SYSTEM\\CurrentControlSet\\Services\\%s", ServiceName);
    if (RegCreateKeyW(HKEY_LOCAL_MACHINE, szKey, &hKey) != ERROR_SUCCESS) {
        return false;
    }

    DWORD dwType = 1; // SERVICE_KERNEL_DRIVER
    DWORD dwStart = 3; // SERVICE_DEMAND_START
    RegSetKeyValueW(hKey, NULL, L"ImagePath", REG_EXPAND_SZ, DriverPath, (DWORD)(wcslen(DriverPath) * 2));
    RegSetKeyValueW(hKey, NULL, L"Type", REG_DWORD, &dwType, sizeof(dwType));
    RegSetKeyValueW(hKey, NULL, L"Start", REG_DWORD, &dwStart, sizeof(dwStart));
    RegCloseKey(hKey);

    // 3. تحميل السائق باستخدام NtLoadDriver
    pNtLoadDriver NtLoadDriver = (pNtLoadDriver)GetProcAddress(hNtdll, "NtLoadDriver");
    if (!NtLoadDriver) return false;

    UNICODE_STRING usService;
    WCHAR szFullPath[512];
    wsprintfW(szFullPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", ServiceName);
    RtlInitUnicodeString(&usService, szFullPath);

    return NtLoadDriver(&usService) == STATUS_SUCCESS;
}

bool UnloadDriverService(LPCWSTR ServiceName) {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;

    pNtUnloadDriver NtUnloadDriver = (pNtUnloadDriver)GetProcAddress(hNtdll, "NtUnloadDriver");
    if (!NtUnloadDriver) return false;

    UNICODE_STRING usService;
    WCHAR szFullPath[512];
    wsprintfW(szFullPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", ServiceName);
    RtlInitUnicodeString(&usService, szFullPath);

    // حذف الـ Registry بعد التفريغ
    WCHAR szKey[512];
    wsprintfW(szKey, L"SYSTEM\\CurrentControlSet\\Services\\%s", ServiceName);
    RegDeleteTreeW(HKEY_LOCAL_MACHINE, szKey);

    return NtUnloadDriver(&usService) == STATUS_SUCCESS;
}