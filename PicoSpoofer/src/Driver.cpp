#include <ntifs.h>
#include "Internals/xdefs.h"
#include "Hooks/HookManager.h"
#include "Hooks/EaBuffer/EaBufferHook.h"
#include "Hooks/FileHooks/FileHooks.h"


namespace
{
	void __fastcall MainHookCallback(
		_In_ unsigned int systemCallIndex,
		_Inout_ void** systemCallFunction)
	{
		UNREFERENCED_PARAMETER(systemCallIndex);

		if (*systemCallFunction == NtCreateFile)
			*systemCallFunction = PicoSpoofer::Hooks::DetourNtCreateFile;
		else if (*systemCallFunction == NtOpenFile)
			*systemCallFunction = PicoSpoofer::Hooks::DetourNtOpenFile;
		else if (*systemCallFunction == NtQueryEaFile)
			*systemCallFunction = PicoSpoofer::Hooks::DetourNtQueryEaFile;
	}
}


extern "C" NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	auto hookManager = PicoSpoofer::HookManager::GetInstance();
	if (hookManager)
	{
		if (const NTSTATUS status = hookManager->Initialize(MainHookCallback); !NT_SUCCESS(status))
		{
			LOG("[-] HookManager init failed: 0x%X\n", status);
			return status;
		}
	}

	LOG("[+] PicoSpoofer loaded. have fun.\n");
	return STATUS_SUCCESS;
}