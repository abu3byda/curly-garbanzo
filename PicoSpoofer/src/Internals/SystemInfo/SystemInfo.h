#pragma once

#include <fltKernel.h>

#include "Internals/xdefs.h"
#define DUMP_BLOCK_SIZE 0X40000
#define KDDEBUGGER_DATA_OFFSET 0x2080

namespace PicoSpoofer
{
	class SystemInfo
	{
	public:
		static SystemInfo* GetInstance();
		static void Destroy();
		static void BypassSignedCheck(PDRIVER_OBJECT drv);
		[[nodiscard]] static KDDEBUGGER_DATA64* GetSystemInfo() { return &_dumpedHeader; }
		static ULONG GetBuildNumber();

	private:
		inline static SystemInfo* _instance;
		inline static KDDEBUGGER_DATA64 _dumpedHeader;
	};
}
