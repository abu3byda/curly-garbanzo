#include "PatternScan.h"

#include <ntddk.h>
#include <ntimage.h>

#include "Internals/xdefs.h"

namespace PicoSpoofer::Utils
{
	void* PatternScan(void* address, size_t size, const char* pattern, const char* mask)
	{
		size -= strlen(mask);

		for (size_t i = 0; i < size; ++i)
		{
			char* p = static_cast<char*>(address) + i;
			if (CheckPattern(p, pattern, mask))
				return p;
		}

		return nullptr;
	}

	void* PatternScanSection(void* moduleBase, const char* pattern, const char* mask, const char* sectionName)
	{

		if (!moduleBase)
		{
			LOG("No module base provided");
			return nullptr;
		}

		const auto dosHeader = static_cast<PIMAGE_DOS_HEADER>(moduleBase);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<char*>(moduleBase) + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		const auto section = IMAGE_FIRST_SECTION(ntHeader);
		for (unsigned short i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
		{
			const PIMAGE_SECTION_HEADER header = &section[i];

			if (strstr(reinterpret_cast<const char*>(header->Name), sectionName))
			{
				void* result = PatternScan(
					static_cast<char*>(moduleBase) + header->VirtualAddress,
					header->Misc.VirtualSize,
					pattern, mask
				);

				if (result)
					return result;
			}
		}

		return nullptr;
	}

	bool CheckPattern(const char* data, const char* pattern, const char* mask)
	{
		const size_t length = strlen(mask);
		for (size_t i = 0; i < length; ++i)
		{
			if (data[i] == pattern[i] || mask[i] == '?')
				continue;
			return false;
		}
		return true;
	}

	bool IsValidPE64(char* base)
	{
		if (!MmIsAddressValid(base)) return false;

		const auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

		const auto ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE) return false;

		return true;
	}
}
