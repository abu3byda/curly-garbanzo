#pragma once

#include <ntifs.h>
#include <windef.h>


namespace PicoSpoofer::Utils
{
	const DWORD x64 = 0x8864;

	void* PatternScan(void* address, size_t size, const char* pattern, const char* mask);

	void* PatternScanSection(void* moduleBase, const char* pattern, const char* mask, const char* sectionName = ".text");

	bool CheckPattern(const char* data, const char* pattern, const char* mask);

	bool IsValidPE64(char* base);

	
}