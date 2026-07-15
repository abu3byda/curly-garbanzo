#pragma once
#include <ntdef.h>
#include <ntifs.h>
#include "ETW/ETWInitializer.h"

typedef void(__fastcall* HOOK_CALLBACK)(_In_ unsigned int systemCallIndex, _Inout_ void** systemCallFunction);

namespace PicoSpoofer
{

	class HookManager
	{
	public:

		HookManager();
		~HookManager();

		NTSTATUS Initialize(HOOK_CALLBACK hookCallback);
		static NTSTATUS Destroy();

		static HookManager* GetInstance()
		{
			if (!_instance)
				_instance = new HookManager();
			return _instance;
		}
	private:

		static void HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd);
		void TraceStackToSyscall();
		void ProcessSyscall(unsigned systemCallIndex, void** stackPosition);


		typedef void (*HalCollectPmcCountersProc)(void*, ULONGLONG);
		static HalCollectPmcCountersProc _originalHalCollectPmcCounters;

		ETWInitializer _etwInitializer;

		bool _initialized;
		static HookManager* _instance;

		static constexpr ULONG _halCollectPmcCountersIndex = 73;
		HOOK_CALLBACK _hookCallback;
		void* _kiSystemServiceRepeat;

	};
}
