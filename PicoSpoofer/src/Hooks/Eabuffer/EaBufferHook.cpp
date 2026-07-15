#include "EaBufferHook.h"
#include "Internals/xdefs.h"
#include "Utils/Utils.h"

namespace
{
	void FakeEaBuffer(const PVOID buffer, const ULONG length, const ULONG64 seed)
	{
		auto entry = static_cast<PFILE_FULL_EA_INFORMATION>(buffer);
		ULONG offset = 0;
		ULONG64 entrySeed = seed;
		while (offset < length)
		{
			if (entry->EaValueLength > 0)
			{
				const PCHAR valuePtr = entry->EaName + entry->EaNameLength + 1;
				for (USHORT i = 0; i < entry->EaValueLength; i++)
				{
					entrySeed ^= (entrySeed << 13);
					entrySeed ^= (entrySeed >> 7);
					entrySeed ^= (entrySeed << 17);
					valuePtr[i] = static_cast<UCHAR>(entrySeed & 0xFF);
				}
			}
			if (entry->NextEntryOffset == 0)
				break;
			offset += entry->NextEntryOffset;
			entry = reinterpret_cast<PFILE_FULL_EA_INFORMATION>(
				static_cast<PUCHAR>(buffer) + offset);
		}
	}
}

namespace PicoSpoofer::Hooks
{
	NTSTATUS DetourNtQueryEaFile(
		_In_ HANDLE FileHandle,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_Out_writes_bytes_(Length) PVOID Buffer,
		_In_ ULONG Length,
		_In_ BOOLEAN ReturnSingleEntry,
		_In_reads_bytes_opt_(EaListLength) PVOID EaList,
		_In_ ULONG EaListLength,
		_In_opt_ PULONG EaIndex,
		_In_ BOOLEAN RestartScan)
	{
		const NTSTATUS status = NtQueryEaFile(
			FileHandle, IoStatusBlock, Buffer, Length,
			ReturnSingleEntry, EaList, EaListLength, EaIndex, RestartScan);
		if (NT_SUCCESS(status) && Buffer && ExGetPreviousMode() == UserMode)
		{
			WCHAR processName[64]{};
			const NTSTATUS nameStatus = Utils::GetProcessImageName(
				PsGetCurrentProcessId(), processName, 64);
			if (NT_SUCCESS(nameStatus) &&
				_wcsnicmp(processName, L"FiveM", 5) == 0)
			{
				const ULONG64 seed = Utils::HashFilename(FileHandle);
				FakeEaBuffer(Buffer, Length, seed);
				LOG("[+] EA buffer changed. Seed=0x%016llX\n", seed);
			}
		}
		return status;
	}
}
