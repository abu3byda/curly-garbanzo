#include "FileHooks.h"
#include "Internals/xdefs.h"
#include "Utils/Utils.h"

namespace PicoSpoofer::Hooks
{
	static bool IsFiveMProcess()
	{
		WCHAR processName[64]{};
		NTSTATUS status = Utils::GetProcessImageName(
			PsGetCurrentProcessId(), processName, 64);
		return NT_SUCCESS(status) && _wcsnicmp(processName, L"FiveM", 5) == 0;
	}

	static bool IsBlockedFilePath(POBJECT_ATTRIBUTES ObjectAttributes)
	{
		if (!ObjectAttributes || !ObjectAttributes->ObjectName ||
			!ObjectAttributes->ObjectName->Buffer || !ObjectAttributes->ObjectName->Length)
			return false;

		PCUNICODE_STRING name = ObjectAttributes->ObjectName;
		const USHORT nameChars = name->Length / sizeof(WCHAR);

		static const WCHAR* blocked[] = {
			L"NvAdminDevice",
			L"NvAPI",
			L"NvMllDdk",
			L"nvml",
			L"clipc"
		};

		for (const auto& pattern : blocked)
		{
			const size_t patLen = wcslen(pattern);
			for (USHORT i = 0; i + patLen <= nameChars; i++)
			{
				if (_wcsnicmp(&name->Buffer[i], pattern, patLen) == 0)
					return true;
			}
		}

		return false;
	}

	NTSTATUS DetourNtCreateFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_ PLARGE_INTEGER AllocationSize,
		_In_ ULONG FileAttributes,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		_In_ ULONG EaLength)
	{
		if (ExGetPreviousMode() == UserMode && IsFiveMProcess() && IsBlockedFilePath(ObjectAttributes))
		{
			//LOG("[+] Blocked NtCreateFile for blocked file path\n");
			return STATUS_ACCESS_DENIED;
		}

		return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		                    IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		                    CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}

	NTSTATUS DetourNtOpenFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG ShareAccess,
		_In_ ULONG OpenOptions)
	{
		if (ExGetPreviousMode() == UserMode && IsFiveMProcess() && IsBlockedFilePath(ObjectAttributes))
		{
			//LOG("[+] Blocked NtOpenFile for blocked file path\n");
			return STATUS_ACCESS_DENIED;
		}

		return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
		                  IoStatusBlock, ShareAccess, OpenOptions);
	}
}
