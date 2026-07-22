#pragma once
#include <windows.h>

extern HANDLE g_hDriver;

bool OpenDriverDevice();
bool SendIOCTL(DWORD IoControlCode, PVOID InputBuffer, DWORD InputSize, PVOID OutputBuffer, DWORD OutputSize);
bool WriteKernelMemory(PVOID Address, PVOID Buffer, SIZE_T Size);
void CloseDriverDevice();