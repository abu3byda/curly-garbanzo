#include "SystemInfo.h"

namespace PicoSpoofer
{
	SystemInfo* SystemInfo::GetInstance()
	{
		UNICODE_STRING keCapturePersistentThreadStateName = RTL_CONSTANT_STRING(L"KeCapturePersistentThreadState");
		char* temp = nullptr;

		do
		{
			if (_instance)
				break;

			_instance = static_cast<SystemInfo*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(SystemInfo), 'msys'));
			if (!_instance)
				break;

			temp = static_cast<char*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, DUMP_BLOCK_SIZE, 'msys'));
			if (!temp)
				break;

			CONTEXT context = {};
			context.ContextFlags = CONTEXT_FULL;
			RtlCaptureContext(&context);

			auto function = reinterpret_cast<void(*)(CONTEXT*, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, void*)>(
				MmGetSystemRoutineAddress(&keCapturePersistentThreadStateName));
			if (!function)
				break;

			function(&context, 0, 0, 0, 0, 0, 0, temp);

			memcpy(&_dumpedHeader, temp + KDDEBUGGER_DATA_OFFSET, sizeof _dumpedHeader);

			if (temp)
				ExFreePoolWithTag(temp, 'msys');

			return _instance;
		}
		while (false);

		if (_instance)
		{
			ExFreePool(_instance);
			_instance = nullptr;
		}

		if (temp)
			ExFreePool(temp);

		return nullptr;
	}

	void SystemInfo::Destroy()
	{
		if (_instance)
		{
			ExFreePool(_instance);
			_instance = nullptr;
		}
	}

	void SystemInfo::BypassSignedCheck(PDRIVER_OBJECT drv)
	{
		//STRUCT FOR WIN64
		typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
		{
			struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
			struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
			struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
			VOID* DllBase;
			VOID* EntryPoint;
			ULONG32 SizeOfImage;
			UINT8 _PADDING0_[0x4];
			struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
			struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
			ULONG32 Flags;
		} LDR_DATA, * PLDR_DATA;
		PLDR_DATA ldr;
		ldr = (PLDR_DATA)(drv->DriverSection);
		ldr->Flags |= 0x20;
	}

	ULONG SystemInfo::GetBuildNumber()
	{
		RTL_OSVERSIONINFOW ver({});
		ULONG ret = 0xffffffff;

		if (NT_SUCCESS(RtlGetVersion(&ver)))
		{
			ret = ver.dwBuildNumber;
		}

		return ret;
	}
}
