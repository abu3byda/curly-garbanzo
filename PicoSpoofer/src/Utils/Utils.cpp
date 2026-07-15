#include "Utils.h"
#include "Internals/xdefs.h"

#include <ntifs.h>
#include <ntstrsafe.h>

namespace PicoSpoofer::Utils
{
	bool EndsWithCaseInsensitive(const PCUNICODE_STRING haystack,
	                             const PCUNICODE_STRING needle)
	{
		if (haystack->Length < needle->Length) return false;
		UNICODE_STRING suffix;
		suffix.Length = needle->Length;
		suffix.MaximumLength = needle->Length;
		suffix.Buffer =
			reinterpret_cast<PWCH>(reinterpret_cast<ULONG_PTR>(haystack->Buffer) +
				(haystack->Length - needle->Length));
		return RtlEqualUnicodeString(&suffix, needle, TRUE);
	}

	void ToLower(char* in, char* out)
	{
		INT i = -1;

		while (in[++i] != '\x00')
		{
			out[i] = static_cast<CHAR>(tolower(in[i]));
		}
	}

	NTSTATUS GetProcessImageName(const HANDLE processId, WCHAR* buffer,
	                             const size_t bufferSize)
	{
		PEPROCESS process;
		NTSTATUS status = PsLookupProcessByProcessId(processId, &process);
		if (!NT_SUCCESS(status)) return status;

		PUNICODE_STRING procName = nullptr;
		status = SeLocateProcessImageName(process, &procName);
		ObDereferenceObject(process);
		if (!NT_SUCCESS(status)) return status;

		const WCHAR* nameStart = wcsrchr(procName->Buffer, L'\\');
		if (!nameStart)
			nameStart = procName->Buffer;
		else
			nameStart++;

		RtlStringCchCopyNW(buffer, bufferSize, nameStart, wcslen(nameStart));

		ExFreePool(procName);
		return STATUS_SUCCESS;
	}

	NTSTATUS WideToString(const wchar_t* src, char* dst, const size_t dstSize)
	{
		if (!src || !dst || dstSize == 0)
		{
			return STATUS_INVALID_PARAMETER;
		}

		size_t i = 0;
		while (src[i] != L'\0' && i < dstSize - 1)
		{
			if (src[i] <= 0x7F)
			{
				dst[i] = static_cast<char>(src[i]);
			}
			else
			{
				dst[i] = '?';
			}
			++i;
		}

		dst[i] = '\0';
		return STATUS_SUCCESS;
	}

	void* GetModuleBase(const wchar_t* moduleName, ULONG* size)
	{
		ULONG needSize = 0;
		ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &needSize);
		void* findBase = 0;
		char moduleNameAscii[256] = {};

		WideToString(moduleName, moduleNameAscii, sizeof(moduleNameAscii));

		const auto info = static_cast<SYSTEM_MODULE_INFORMATION*>(
			ExAllocatePool2(POOL_FLAG_NON_PAGED, needSize, 'msU'));

		if (!info)
		{
			return nullptr;
		}

		do
		{
			if (!NT_SUCCESS(ZwQuerySystemInformation(SystemModuleInformation, info, needSize, &needSize)))
			{
				break;
			}

			for (size_t i = 0; i < info->Count; ++i)
			{
				const SYSTEM_MODULE_ENTRY* moduleEntry = &info->Module[i];
				const char* lastSlash = strrchr(moduleEntry->Name, '\\');
				if (lastSlash)
				{
					lastSlash++;
				}
				else
				{
					lastSlash = moduleEntry->Name;
				}

				if (!_strnicmp(lastSlash, moduleNameAscii, strlen(moduleNameAscii)))
				{
					findBase = moduleEntry->BaseAddress;
					if (size)
						*size = moduleEntry->Size;
					break;
				}
			}
		}
		while (false);

		if (info)
			ExFreePoolWithTag(info, 'msU');

		return findBase;
	}

	bool IsFiveMProcess(const PEPROCESS process)
	{
		if (!process)
			return false;

		WCHAR processName[64]{};
		if (const NTSTATUS status = GetProcessImageName(PsGetProcessId(process), processName, 64); !NT_SUCCESS(status))
			return false;

		return _wcsnicmp(processName, L"FiveM", 5) == 0;
	}

	ULONG64 HashFilename(const HANDLE fileHandle)
	{
		UCHAR nameBuffer[512]{};
		IO_STATUS_BLOCK ioStatusBlock{};
		const NTSTATUS status = ZwQueryInformationFile(
			fileHandle, &ioStatusBlock,
			nameBuffer, sizeof(nameBuffer),
			FileNameInformation);
		if (!NT_SUCCESS(status))
			return 0xDEADBEEFDEADBEEF;
		const auto nameInfo = reinterpret_cast<PFILE_NAME_INFORMATION>(nameBuffer);

		ULONG64 hash = 0xCBF29CE484222325;
		const auto bytes = reinterpret_cast<PUCHAR>(nameInfo->FileName);
		for (ULONG i = 0; i < nameInfo->FileNameLength; i++)
		{
			hash ^= bytes[i];
			hash *= 0x00000100000001B3;
		}
		constexpr INT64 buildSeed = 0xC12BBA23ADBA;
		hash ^= static_cast<ULONG64>(buildSeed);
		return hash;
	}
}


void* operator new(size_t size)
{
	return ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'wNeK');
}

void* operator new(size_t size, POOL_FLAGS flags, ULONG tag)
{
	return ExAllocatePool2(flags, size, tag);
}

void operator delete(void* ptr)
{
	if (ptr)
		ExFreePool(ptr);
}

void operator delete(void* ptr, size_t)
{
	if (ptr)
		ExFreePool(ptr);
}
