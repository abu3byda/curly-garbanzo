#pragma once
#include <windows.h>

bool LoadDriverAsService(LPCWSTR ServiceName, LPCWSTR DriverPath);
bool UnloadDriverService(LPCWSTR ServiceName);