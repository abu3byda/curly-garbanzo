#pragma once

#include <ntifs.h>

namespace PicoSpoofer::Utils
{
	bool EndsWithCaseInsensitive(PCUNICODE_STRING haystack,
	                                    PCUNICODE_STRING needle);

	void ToLower(char* in, char* out);

	NTSTATUS GetProcessImageName(HANDLE processId, WCHAR* buffer,
	                             size_t bufferSize);

	NTSTATUS WideToString(const wchar_t* src, char* dst, size_t dstSize);

	void* GetModuleBase(const wchar_t* moduleName, ULONG* size);

	bool IsFiveMProcess(const PEPROCESS process);

	ULONG64 HashFilename(const HANDLE fileHandle);
}

void* operator new(size_t size);
void* operator new(size_t size, POOL_FLAGS flags, ULONG tag);
void operator delete(void* ptr);
void operator delete(void* ptr, size_t);
