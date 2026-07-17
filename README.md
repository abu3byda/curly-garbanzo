Project code collected from: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer

------------------------------------------------------------------------------------------

==========================================================================================
FILE #4
RELATIVE PATH: PicoSpoofer\src\Driver.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Driver.cpp
SIZE: 1218 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#include <ntifs.h>
#include "Internals/xdefs.h"
#include "Hooks/HookManager.h"
#include "Hooks/EaBuffer/EaBufferHook.h"
#include "Hooks/FileHooks/FileHooks.h"


namespace
{
	void __fastcall MainHookCallback(
		_In_ unsigned int systemCallIndex,
		_Inout_ void** systemCallFunction)
	{
		UNREFERENCED_PARAMETER(systemCallIndex);

		if (*systemCallFunction == NtCreateFile)
			*systemCallFunction = PicoSpoofer::Hooks::DetourNtCreateFile;
		else if (*systemCallFunction == NtOpenFile)
			*systemCallFunction = PicoSpoofer::Hooks::DetourNtOpenFile;
		else if (*systemCallFunction == NtQueryEaFile)
			*systemCallFunction = PicoSpoofer::Hooks::DetourNtQueryEaFile;
	}
}


extern "C" NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	auto hookManager = PicoSpoofer::HookManager::GetInstance();
	if (hookManager)
	{
		if (const NTSTATUS status = hookManager->Initialize(MainHookCallback); !NT_SUCCESS(status))
		{
			LOG("[-] HookManager init failed: 0x%X\n", status);
			return status;
		}
	}

	LOG("[+] PicoSpoofer loaded. have fun.\n");
	return STATUS_SUCCESS;
}
------------------------------------------------------------------------------------------

==========================================================================================
FILE #5
RELATIVE PATH: PicoSpoofer\src\ETW\ETWInitializer.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\ETW\ETWInitializer.cpp
SIZE: 7478 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#include "ETWInitializer.h"

#include <ntifs.h>

#include "Internals/xdefs.h"
#include "Internals/SystemInfo/SystemInfo.h"

#include "Utils/Utils.h"
#include "Utils/PatternScan/PatternScan.h"

namespace PicoSpoofer
{
	ULONG ETWInitializer::_loggerId = 0;

	ETWInitializer::ETWInitializer()
	{
		_active = false;
		_halPrivateDispatchTable = nullptr;

		UNICODE_STRING functionName = {};
		RtlInitUnicodeString(&functionName, L"HalPrivateDispatchTable");
		_halPrivateDispatchTable = static_cast<UINT_PTR*>(MmGetSystemRoutineAddress(&functionName));

		if (!_halPrivateDispatchTable)
		{
			LOG("!![-]!! Failed to get HalPrivateDispatchTable\n");
		}
	}

	ETWInitializer::~ETWInitializer()
	{
		EndTrace();
	}

	NTSTATUS ETWInitializer::StartTrace()
	{
		if (_active)
			return STATUS_SUCCESS;

		const NTSTATUS status = StartStopTrace(true);
		if (NT_SUCCESS(status))
			_active = true;

		return status;
	}

	NTSTATUS ETWInitializer::EndTrace()
	{
		if (!_active)
			return STATUS_SUCCESS;

		const NTSTATUS status = StartStopTrace(false);
		if (NT_SUCCESS(status))
			_active = false;

		return status;
	}

	unsigned char* ETWInitializer::GetEtwpMaxPmcCounter()
	{
		//PAGE:00000001409DB8DE 44 3B 05 57 57 37 00                          cmp     r8d, cs:EtwpMaxPmcCounter
		//PAGE : 00000001409DB8E5 0F 87 EC 00 00 00                           ja      loc_1409DB9D7
		//PAGE : 00000001409DB8EB 83 B9 2C 01 00 00 01                        cmp     dword ptr[rcx + 12Ch], 1
		//PAGE:00000001409DB8F2 0F 84 DF 00 00 00                             jz      loc_1409DB9D7
		//PAGE : 00000001409DB8F8 48 83 B9 F8 03 00 00 00                     cmp     qword ptr[rcx + 3F8h], 0
		//PAGE:00000001409DB900 75 0D                                         jnz     short loc_1409DB90F

		if (SystemInfo::GetInstance()->GetBuildNumber() < 18362)
			return nullptr;

		void* kernelImageBase = Utils::GetModuleBase(L"ntoskrnl.exe", nullptr);
		if (!kernelImageBase)
		{
			return nullptr;
		}

		void* data = Utils::PatternScanSection(kernelImageBase,
		                                       "\x44\x3b\x05\x00\x00\x00\x00\x0f\x87\x00\x00\x00\x00\x83\xb9\x00\x00\x00\x00\x01\x0f\x84\x00\x00\x00\x00\x48\x83\xb9\x00\x00\x00\x00\x00\x75\x00",
		                                       "xxx????xx????xx????xxx????xxx????xx?",
		                                       "PAGE"
		);

		if (data)
		{
			const LONG offset = *reinterpret_cast<const LONG*>(static_cast<const char*>(data) + 3);
			return static_cast<unsigned char*>(data) + 7 + offset;
		}
		return nullptr;
	}

	NTSTATUS ETWInitializer::OpenPmcCounter()
	{
		auto status = STATUS_SUCCESS;
		PEVENT_TRACE_PROFILE_COUNTER_INFORMATION countInfo = nullptr;
		PEVENT_TRACE_SYSTEM_EVENT_INFORMATION eventInfo = nullptr;

		if (!_active)
			return STATUS_FLT_NOT_INITIALIZED;

		ULONG loggerId = _loggerId;
		if (loggerId == 0)
		{
			auto etwpDebuggerData = reinterpret_cast<ULONG***>(
				SystemInfo::GetInstance()->GetSystemInfo()->EtwpDebuggerData);
			if (!etwpDebuggerData)
			{
				LOG("!![-]!! Failed to get EtwpDebuggerData\n");
				return STATUS_NOT_SUPPORTED;
			}
			loggerId = etwpDebuggerData[2][2][0];
		}

		countInfo = static_cast<EVENT_TRACE_PROFILE_COUNTER_INFORMATION*>
			(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(EVENT_TRACE_PROFILE_COUNTER_INFORMATION), 'cntI'));

		if (!countInfo)
		{
			LOG("[-] Failed to get countInfo\n");
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		//First set PMC Count. We only care about one hookid, which is the hookid of syscall 0xf33 profile source. Set it casually.
		countInfo->EventTraceInformationClass = EventTraceProfileCounterListInformation;
		countInfo->TraceHandle = ULongToHandle(loggerId);
		countInfo->ProfileSource[0] = 1;

		unsigned char* etwpMaxPmcCounter = GetEtwpMaxPmcCounter();

		unsigned char original = 0;
		if (etwpMaxPmcCounter)
		{
			original = *etwpMaxPmcCounter;
			if (original <= 1)
				*etwpMaxPmcCounter = 2;
		}
		else
		{
			LOG("[-] EtwpMaxPmcCounter pattern not found!\n");
		}
		status = ZwSetSystemInformation(SystemPerformanceTraceInformation, countInfo,
		                                sizeof EVENT_TRACE_PROFILE_COUNTER_INFORMATION);
		if (etwpMaxPmcCounter)
		{
			if (original <= 1)
				*etwpMaxPmcCounter = original;
		}

		if (!NT_SUCCESS(status))
		{
			LOG("[-] Failed to set system information for PMC counter\n");
			ExFreePoolWithTag(countInfo, 'cntI');
			return STATUS_ACCESS_DENIED;
		}

		eventInfo = static_cast<EVENT_TRACE_SYSTEM_EVENT_INFORMATION*>(ExAllocatePool2(
			POOL_FLAG_NON_PAGED, sizeof(EVENT_TRACE_SYSTEM_EVENT_INFORMATION), 'evtI'));
		if (!eventInfo)
		{
			LOG("[-] Failed to allocate memory for eventInfo\n");
			ExFreePoolWithTag(countInfo, 'cntI');
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		eventInfo->EventTraceInformationClass = EventTraceProfileEventListInformation;
		eventInfo->TraceHandle = ULongToHandle(loggerId);
		eventInfo->HookId[0] = _syscallId;

		status = ZwSetSystemInformation(SystemPerformanceTraceInformation, eventInfo,
		                                sizeof EVENT_TRACE_SYSTEM_EVENT_INFORMATION);
		if (!NT_SUCCESS(status))
		{
			LOG("Failed to set system information for eventInfo\n");
			ExFreePoolWithTag(countInfo, 'cntI');
			ExFreePoolWithTag(eventInfo, 'evtI');
			return STATUS_ACCESS_DENIED;
		}

		ExFreePoolWithTag(countInfo, 'cntI');
		ExFreePoolWithTag(eventInfo, 'evtI');

		return status;
	}

	NTSTATUS ETWInitializer::StartStopTrace(const bool start)
	{
		auto status = STATUS_UNSUCCESSFUL;
		ULONG lengthReturned = 0;

		auto ckclTraceProperties = static_cast<CKCL_TRACE_PROPERTIES*>(ExAllocatePool2(
			POOL_FLAG_NON_PAGED, PAGE_SIZE, 'trcP'));
		if (!ckclTraceProperties)
		{
			LOG("[-] Failed to allocate memory for ckclTraceProperties\n");
			return STATUS_MEMORY_NOT_ALLOCATED;
		}

		memset(ckclTraceProperties, 0, PAGE_SIZE);
		ckclTraceProperties->Wnode.BufferSize = PAGE_SIZE;
		ckclTraceProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
		ckclTraceProperties->ProviderName = RTL_CONSTANT_STRING(L"Circular Kernel Context Logger");
		ckclTraceProperties->Wnode.Guid = CkclSessionGuid;
		ckclTraceProperties->Wnode.ClientContext = 1;
		ckclTraceProperties->BufferSize = sizeof(ULONG);
		ckclTraceProperties->MinimumBuffers = ckclTraceProperties->MaximumBuffers = 2;
		ckclTraceProperties->LogFileMode = EVENT_TRACE_BUFFERING_MODE;

		status = ZwTraceControl(start ? EtwpStartTrace : EtwpStopTrace,
		                        ckclTraceProperties, PAGE_SIZE, ckclTraceProperties, PAGE_SIZE, &lengthReturned);

		if (!NT_SUCCESS(status) && status != STATUS_OBJECT_NAME_COLLISION)
		{
			LOG("[-] Failed to start/stop trace: 0x%X\n", status);
			ExFreePoolWithTag(ckclTraceProperties, 'trcP');
			return status;
		}

		if (start)
		{
			_loggerId = static_cast<ULONG>(ckclTraceProperties->Wnode.HistoricalContext);
			ckclTraceProperties->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;

			status = ZwTraceControl(EtwpUpdateTrace, ckclTraceProperties, PAGE_SIZE, ckclTraceProperties, PAGE_SIZE,
			                        &lengthReturned);
			if (!NT_SUCCESS(status))
			{
				StartStopTrace(false);
				return status;
			}
		}

		if (ckclTraceProperties)
			ExFreePoolWithTag(ckclTraceProperties, 'trcP');


		return status;
	}
}

------------------------------------------------------------------------------------------

==========================================================================================
FILE #6
RELATIVE PATH: PicoSpoofer\src\ETW\ETWInitializer.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\ETW\ETWInitializer.h
SIZE: 657 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#pragma once
#include <ntdef.h>

namespace PicoSpoofer
{
	class ETWInitializer
	{
	public:

		ETWInitializer();
		~ETWInitializer();
		ETWInitializer(const ETWInitializer&) = delete;
		ETWInitializer& operator=(const ETWInitializer&) = delete;

		NTSTATUS StartTrace();
		NTSTATUS EndTrace();

		unsigned char* GetEtwpMaxPmcCounter();
		NTSTATUS OpenPmcCounter();


		[[nodiscard]] UINT_PTR* GetHalPrivateDispatchTable() const
		{
			return _halPrivateDispatchTable;
		}


	private:
		static NTSTATUS StartStopTrace(bool start);

		bool _active;
		UINT_PTR* _halPrivateDispatchTable;
		
		static ULONG _loggerId;

	};
}

------------------------------------------------------------------------------------------

==========================================================================================
FILE #7
RELATIVE PATH: PicoSpoofer\src\Hooks\Eabuffer\EaBufferHook.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Hooks\Eabuffer\EaBufferHook.cpp
SIZE: 1914 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------

==========================================================================================
FILE #8
RELATIVE PATH: PicoSpoofer\src\Hooks\Eabuffer\EaBufferHook.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Hooks\Eabuffer\EaBufferHook.h
SIZE: 846 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#pragma once
#include <ntifs.h>

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtQueryEaFile(
    _In_ HANDLE FileHandle,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock,
    _Out_writes_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_reads_bytes_opt_(EaListLength) PVOID EaList,
    _In_ ULONG EaListLength,
    _In_opt_ PULONG EaIndex,
    _In_ BOOLEAN RestartScan);

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
        _In_ BOOLEAN RestartScan);
}
------------------------------------------------------------------------------------------

==========================================================================================
FILE #9
RELATIVE PATH: PicoSpoofer\src\Hooks\FileHooks\FileHooks.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Hooks\FileHooks\FileHooks.cpp
SIZE: 2535 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#include "FileHooks.h"
#include "Internals/xdefs.h"
#include "Utils/Utils.h"

namespace PicoSpoofer::Hooks
{
	static bool IsFiveMProcess()
	{
		WCHAR processName[64]{};
		NTSTATUS status = Utils::GetProcessImageName(
			PsGetCurrentProcessId(), processName, 64);
		return NT_SUCCESS(status) && _wcsnicmp(processName, L"FiveM", 5) == 0;
	}

	static bool IsBlockedFilePath(POBJECT_ATTRIBUTES ObjectAttributes)
	{
		if (!ObjectAttributes || !ObjectAttributes->ObjectName ||
			!ObjectAttributes->ObjectName->Buffer || !ObjectAttributes->ObjectName->Length)
			return false;

		PCUNICODE_STRING name = ObjectAttributes->ObjectName;
		const USHORT nameChars = name->Length / sizeof(WCHAR);

		static const WCHAR* blocked[] = {
			L"NvAdminDevice",
			L"NvAPI",
			L"NvMllDdk",
			L"nvml",
			L"clipc"
		};

		for (const auto& pattern : blocked)
		{
			const size_t patLen = wcslen(pattern);
			for (USHORT i = 0; i + patLen <= nameChars; i++)
			{
				if (_wcsnicmp(&name->Buffer[i], pattern, patLen) == 0)
					return true;
			}
		}

		return false;
	}

	NTSTATUS DetourNtCreateFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_opt_ PLARGE_INTEGER AllocationSize,
		_In_ ULONG FileAttributes,
		_In_ ULONG ShareAccess,
		_In_ ULONG CreateDisposition,
		_In_ ULONG CreateOptions,
		_In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
		_In_ ULONG EaLength)
	{
		if (ExGetPreviousMode() == UserMode && IsFiveMProcess() && IsBlockedFilePath(ObjectAttributes))
		{
			//LOG("[+] Blocked NtCreateFile for blocked file path\n");
			return STATUS_ACCESS_DENIED;
		}

		return NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
		                    IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
		                    CreateDisposition, CreateOptions, EaBuffer, EaLength);
	}

	NTSTATUS DetourNtOpenFile(
		_Out_ PHANDLE FileHandle,
		_In_ ACCESS_MASK DesiredAccess,
		_In_ POBJECT_ATTRIBUTES ObjectAttributes,
		_Out_ PIO_STATUS_BLOCK IoStatusBlock,
		_In_ ULONG ShareAccess,
		_In_ ULONG OpenOptions)
	{
		if (ExGetPreviousMode() == UserMode && IsFiveMProcess() && IsBlockedFilePath(ObjectAttributes))
		{
			//LOG("[+] Blocked NtOpenFile for blocked file path\n");
			return STATUS_ACCESS_DENIED;
		}

		return NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
		                  IoStatusBlock, ShareAccess, OpenOptions);
	}
}

------------------------------------------------------------------------------------------

==========================================================================================
FILE #10
RELATIVE PATH: PicoSpoofer\src\Hooks\FileHooks\FileHooks.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Hooks\FileHooks\FileHooks.h
SIZE: 832 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#pragma once
#include <ntifs.h>

namespace PicoSpoofer::Hooks
{
    NTSTATUS DetourNtCreateFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_opt_ PLARGE_INTEGER AllocationSize,
        _In_ ULONG FileAttributes,
        _In_ ULONG ShareAccess,
        _In_ ULONG CreateDisposition,
        _In_ ULONG CreateOptions,
        _In_reads_bytes_opt_(EaLength) PVOID EaBuffer,
        _In_ ULONG EaLength);

    NTSTATUS DetourNtOpenFile(
        _Out_ PHANDLE FileHandle,
        _In_ ACCESS_MASK DesiredAccess,
        _In_ POBJECT_ATTRIBUTES ObjectAttributes,
        _Out_ PIO_STATUS_BLOCK IoStatusBlock,
        _In_ ULONG ShareAccess,
        _In_ ULONG OpenOptions);
}
------------------------------------------------------------------------------------------

==========================================================================================
FILE #11
RELATIVE PATH: PicoSpoofer\src\Hooks\HookManager.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Hooks\HookManager.cpp
SIZE: 7273 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#include "HookManager.h"

#include <intrin.h>

#include "Internals/SystemInfo/SystemInfo.h"

#include "Utils/Utils.h"
#include "Utils/PatternScan/PatternScan.h"

#define OFFSET_KPCR_CURRENT_THREAD  0x188
#define OFFSET_KPCR_RSP_BASE        0x1A8
#define OFFSET_KTHREAD_SYSTEM_CALL_NUMBER 0x80


namespace PicoSpoofer
{
	HookManager* HookManager::_instance = nullptr;
	HookManager::HalCollectPmcCountersProc
	HookManager::_originalHalCollectPmcCounters = nullptr;

	HookManager::HookManager() : _initialized(false), _hookCallback(nullptr), _kiSystemServiceRepeat(nullptr)
	{
		void* kernelImageBase = Utils::GetModuleBase(L"ntoskrnl.exe", nullptr);

		//KiSystemServiceRepeat:
		//	4C 8D 15 85 6F 9F 00          lea     r10, KeServiceDescriptorTable
		//	4C 8D 1D FE 20 8F 00          lea     r11, KeServiceDescriptorTableShadow
		//	F7 43 78 80 00 00 00          test    dword ptr[rbx + 78h], 80h; GuiThread
		//KiSystemServiceRepeat must be located in KiSystemCall64, which directly searches for the signature code

		_kiSystemServiceRepeat = Utils::PatternScanSection(kernelImageBase,
		                                                   "\x4c\x8d\x15\x00\x00\x00\x00\x4c\x8d\x1d\x00\x00\x00\x00\xf7\x43",
		                                                   "xxx????xxx????xx", ".text");
	}

	HookManager::~HookManager()
	{
		if (_originalHalCollectPmcCounters)
		{
			_disable();
			_etwInitializer.GetHalPrivateDispatchTable()[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(
				_originalHalCollectPmcCounters);
			_enable();
		}
	}

	NTSTATUS HookManager::Initialize(HOOK_CALLBACK hookCallback)
	{
		if (!_instance)
			return STATUS_MEMORY_NOT_ALLOCATED; // 0xC00000A0L
		if (_initialized)
			return STATUS_SUCCESS;

		auto status = STATUS_UNSUCCESSFUL;

		auto systemInfo = SystemInfo::GetInstance();
		if (!systemInfo)
			return STATUS_INSUFFICIENT_RESOURCES;

		if (systemInfo->GetBuildNumber() <= 7601)
			return STATUS_NOT_SUPPORTED;

		status = _etwInitializer.StartTrace();
		if (!NT_SUCCESS(status))
		{
			LOG("Failed to start ETW trace with status: 0x%X\n", status);
			return status;
		}

		status = _etwInitializer.OpenPmcCounter();
		if (!NT_SUCCESS(status))
		{
			LOG("Failed to open PMC counter with status: 0x%X\n", status);
			return status;
		}

		UINT_PTR* halPrivateDispatchTable = _etwInitializer.GetHalPrivateDispatchTable();
		if (!halPrivateDispatchTable)
		{
			LOG("Failed to get HalPrivateDispatchTable\n");
			return STATUS_NOT_SUPPORTED;
		}

		_disable();
		_originalHalCollectPmcCounters = reinterpret_cast<HalCollectPmcCountersProc>(halPrivateDispatchTable[
			_halCollectPmcCountersIndex]);
		halPrivateDispatchTable[_halCollectPmcCountersIndex] = reinterpret_cast<ULONG_PTR>(HalCollectPmcCountersHook);
		_enable();

		_hookCallback = hookCallback;
		_initialized = true;

		return status;
	}

	NTSTATUS HookManager::Destroy()
	{
		if (!_instance)
			return STATUS_MEMORY_NOT_ALLOCATED;
		delete _instance;
		_instance = nullptr;
		return STATUS_SUCCESS;
	}


	void HookManager::HalCollectPmcCountersHook(void* context, ULONGLONG traceBufferEnd)
	{
		if (KeGetCurrentIrql() <= DISPATCH_LEVEL)
		{
			if (_instance)
				_instance->TraceStackToSyscall();
		}
		return _originalHalCollectPmcCounters(context, traceBufferEnd);
	}

	void HookManager::TraceStackToSyscall()
	{
		if (ExGetPreviousMode() == KernelMode)
			return;

		const ULONG64 currentThread = __readgsqword(OFFSET_KPCR_CURRENT_THREAD);
		const unsigned syscallIndex = *reinterpret_cast<unsigned*>(currentThread + OFFSET_KTHREAD_SYSTEM_CALL_NUMBER);

		if (syscallIndex == 0 || syscallIndex >= 0x0200)
			return;

		if (!_kiSystemServiceRepeat || !MmIsAddressValid(_kiSystemServiceRepeat))
			return;
		/*
		* 25h2 fix documentation
		after logging everything, patterns structs offsets etc. it was all correct but after debugging with windbg
	
		kd> bp nt!NtCreateFile
		kd> dps @rsp L30
		ffffa887`4fd3f3e8 fffff801`f0eb3944 nt!KiSystemServiceExitPico+0x499
		ffffa887`4fd3f458 fffff801`f0eb2e3b nt!KiSystemServiceUser+0x59
	
		look at those addresses from the stack:
		nt!KiSystemServiceExitPico+0x499
		nt!KiSystemServiceUser+0x59
	
		kd> ? nt!KiSystemServiceExitPico - nt!KiSystemServiceRepeat
		kd> ? nt!KiSystemServiceUser - nt!KiSystemServiceRepeat
	
		these are syscall exit paths that are outside the 4KB range from
		(cant really see that they are out of range, didnt include full logs bcs too much)
	
		we can see both are out of range since we were on 0x1000 (PAGE_SIZE)
		increased the page size by * 4 so we can get 16kb which fixed the issue
		*/

		const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(PAGE_ALIGN(_kiSystemServiceRepeat));
		const ULONG_PTR end = base + (PAGE_SIZE * 4); // increased for 25h2

		auto stackPos = reinterpret_cast<PVOID*>(_AddressOfReturnAddress());
		const auto stackLimit = reinterpret_cast<PVOID*>(__readgsqword(OFFSET_KPCR_RSP_BASE));

		__try
		{
			for (; stackPos < stackLimit; ++stackPos)
			{
				const ULONG_PTR retAddr = reinterpret_cast<ULONG_PTR>(*stackPos);
				if (retAddr >= base && retAddr < end)
				{
					ProcessSyscall(syscallIndex, stackPos);
					break;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}

	static void* g_HookedSyscalls[0x200] = {nullptr};
	static void* g_OriginalSyscalls[0x200] = {nullptr};

	void HookManager::ProcessSyscall(unsigned systemCallIndex, void** stackPosition)
	{
		if (!_hookCallback)
			return;
		/*
		* crash fix documentation
		(Bug Check 0x3B - SYSTEM_SERVICE_EXCEPTION)
		during debugging the stack trace i found that PerfInfoLogSysCallEntry
		rip rsp rbp is corrupt
	
		-------------------
		kd> .trap 0xFFFFFC021C506900
		NOTE: The trap frame does not contain all registers.
		Unable to get program counter
		rax=00001f800010001f rbx=0000000000000000 rcx=0053002b002b0010
		rdx=000502820018002b rsi=0000000000000000 rdi=0000000000000000
		rip=0000000000000000 rsp=0000000000000000 rbp=0000000000000000
		r8=0000000000000000  r9=fffffc021c507370 r10=ffffbb8bc391a000
		r11=ffffbb8bc379ba10 r12=0000000000000000 r13=0000000000000000
		r14=0000000000000000 r15=0000000000000000
		iopl=0         nv up di pl nz na pe nc
		6420:0000 ??              ???
		-------------------
		*/

		PVOID* stackLimit = reinterpret_cast<PVOID*>(__readgsqword(OFFSET_KPCR_RSP_BASE));
		if (!stackLimit || (stackPosition + 9) >= stackLimit)
			return;

		__try
		{
			void* currentSyscallFunc = stackPosition[9];

			if (g_HookedSyscalls[systemCallIndex] != nullptr)
			{
				if (currentSyscallFunc == g_OriginalSyscalls[systemCallIndex])
				{
					stackPosition[9] = g_HookedSyscalls[systemCallIndex];
				}
				return;
			}

			void* syscallFuncCopy = currentSyscallFunc;
			_hookCallback(systemCallIndex, &syscallFuncCopy);

			if (syscallFuncCopy != currentSyscallFunc)
			{
				g_OriginalSyscalls[systemCallIndex] = currentSyscallFunc;
				g_HookedSyscalls[systemCallIndex] = syscallFuncCopy;

				stackPosition[9] = syscallFuncCopy;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			return;
		}
	}
}

------------------------------------------------------------------------------------------

==========================================================================================
FILE #12
RELATIVE PATH: PicoSpoofer\src\Hooks\HookManager.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Hooks\HookManager.h
SIZE: 1082 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------

==========================================================================================
FILE #13
RELATIVE PATH: PicoSpoofer\src\Internals\SystemInfo\SystemInfo.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Internals\SystemInfo\SystemInfo.cpp
SIZE: 2444 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------

==========================================================================================
FILE #14
RELATIVE PATH: PicoSpoofer\src\Internals\SystemInfo\SystemInfo.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Internals\SystemInfo\SystemInfo.h
SIZE: 553 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------

==========================================================================================
FILE #15
RELATIVE PATH: PicoSpoofer\src\Internals\xdefs.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Internals\xdefs.h
SIZE: 16155 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
#pragma once
#include <ntifs.h>


#ifdef DBG
#define LOG(format, ...) DbgPrintEx(0, 0, format, ##__VA_ARGS__)

#else
#define LOG(format, ...) ((void)0)

#endif

using BYTE = unsigned char;


extern "C" {
NTSTATUS NTAPI ZwProtectVirtualMemory(_In_ HANDLE ProcessHandle,
                                      _Inout_ PVOID* BaseAddress,
                                      _Inout_ PSIZE_T RegionSize,
                                      _In_ ULONG NewProtection,
                                      _Out_ PULONG OldProtection);

NTSTATUS
ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation,
                         ULONG SystemInformationLength, PULONG ReturnLength);

NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);

NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);
}



EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwSetSystemInformation(ULONG infoClass, void* buf, ULONG length);


typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _SYSTEM_MODULE_ENTRY
{
	ULONGLONG Unknown1;
	ULONGLONG Unknown2;
	PVOID BaseAddress;
	ULONG Size;
	ULONG Flags;
	ULONG EntryIndex;
	USHORT NameLength;  // Length of module name not including the path, this field contains valid value only for NTOSKRNL module
	USHORT PathLength;  // Length of 'directory path' part of modulename
	CHAR Name[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE_ENTRY;


typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG Count;
	ULONG Unknown1;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
  *PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;



//TRACE

enum EtwpTrace
{
	EtwpStartTrace      = 1,
	EtwpStopTrace       = 2,
	EtwpQueryTrace      = 3,
	EtwpUpdateTrace     = 4,
	EtwpFlushTrace      = 5
};


constexpr auto  _syscallId = 0xf33ul;

#define WNODE_FLAG_TRACED_GUID			0x00020000  // denotes a trace
#define EVENT_TRACE_BUFFERING_MODE      0x00000400  // Buffering mode only
#define EVENT_TRACE_FLAG_SYSTEMCALL     0x00000080  // system calls

typedef struct _WNODE_HEADER
{
	ULONG BufferSize;        // Size of entire buffer inclusive of this ULONG
	ULONG ProviderId;    // Provider Id of driver returning this buffer
	union
	{
		ULONG64 HistoricalContext;  // Logger use
		struct
		{
			ULONG Version;           // Reserved
			ULONG Linkage;           // Linkage field reserved for WMI
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

	union
	{
		ULONG CountLost;         // Reserved
		HANDLE KernelHandle;     // Kernel handle for data block
		LARGE_INTEGER TimeStamp; // Timestamp as returned in units of 100ns
								 // since 1/1/1601
	} DUMMYUNIONNAME2;
	GUID Guid;                  // Guid for data block returned with results
	ULONG ClientContext;
	ULONG Flags;             // Flags, see below
} WNODE_HEADER;

#pragma warning(default : 4201)

typedef struct _EVENT_TRACE_PROPERTIES
{
	WNODE_HEADER	Wnode;
	ULONG			BufferSize;
	ULONG			MinimumBuffers;
	ULONG			MaximumBuffers;
	ULONG			MaximumFileSize;
	ULONG			LogFileMode;
	ULONG			FlushTimer;
	ULONG			EnableFlags;
	LONG			AgeLimit;
	ULONG			NumberOfBuffers;
	ULONG			FreeBuffers;
	ULONG			EventsLost;
	ULONG			BuffersWritten;
	ULONG			LogBuffersLost;
	ULONG			RealTimeBuffersLost;
	HANDLE			LoggerThreadId;
	ULONG			LogFileNameOffset;
	ULONG			LoggerNameOffset;
} EVENT_TRACE_PROPERTIES;

const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };

const GUID NtklSessionGuid = { 0x9E814AAD, 0x3204, 0x11D2, { 0x9A, 0x82, 0x0, 0x60, 0x8, 0xA8, 0x69, 0x39 } };

typedef struct _CKCL_TRACE_PROPERIES : EVENT_TRACE_PROPERTIES
{
	ULONG64					Unknown[3];
	UNICODE_STRING			ProviderName;
} CKCL_TRACE_PROPERTIES;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
ZwTraceControl(
	_In_ ULONG FunctionCode,
	_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
	_In_ ULONG InBufferLen,
	_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
	_In_ ULONG OutBufferLen,
	_Out_ PULONG ReturnLength
);

EXTERN_C


typedef enum _EVENT_TRACE_INFORMATION_CLASS
{
	EventTraceKernelVersionInformation,
	EventTraceGroupMaskInformation,
	EventTracePerformanceInformation,
	EventTraceTimeProfileInformation,
	EventTraceSessionSecurityInformation,
	EventTraceSpinlockInformation,
	EventTraceStackTracingInformation,
	EventTraceExecutiveResourceInformation,
	EventTraceHeapTracingInformation,
	EventTraceHeapSummaryTracingInformation,
	EventTracePoolTagFilterInformation,
	EventTracePebsTracingInformation,
	EventTraceProfileConfigInformation,
	EventTraceProfileSourceListInformation,
	EventTraceProfileEventListInformation,
	EventTraceProfileCounterListInformation,
	EventTraceStackCachingInformation,
	EventTraceObjectTypeFilterInformation,
	MaxEventTraceInfoClass
} EVENT_TRACE_INFORMATION_CLASS;

typedef struct _EVENT_TRACE_PROFILE_COUNTER_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG ProfileSource[1];
} EVENT_TRACE_PROFILE_COUNTER_INFORMATION, * PEVENT_TRACE_PROFILE_COUNTER_INFORMATION;

typedef struct _EVENT_TRACE_SYSTEM_EVENT_INFORMATION
{
	EVENT_TRACE_INFORMATION_CLASS EventTraceInformationClass;
	HANDLE TraceHandle;
	ULONG HookId[1];
} EVENT_TRACE_SYSTEM_EVENT_INFORMATION, * PEVENT_TRACE_SYSTEM_EVENT_INFORMATION;

const ULONG SystemPerformanceTraceInformation = 31;



typedef struct _DBGKD_DEBUG_DATA_HEADER64
		{
			LIST_ENTRY64 List;
			ULONG           OwnerTag;
			ULONG           Size;
		} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64
		{

			DBGKD_DEBUG_DATA_HEADER64 Header;

			//
			// Base address of kernel image
			//

			ULONG64   KernBase;

			//
			// DbgBreakPointWithStatus is a function which takes an argument
			// and hits a breakpoint.  This field contains the address of the
			// breakpoint instruction.  When the debugger sees a breakpoint
			// at this address, it may retrieve the argument from the first
			// argument register, or on x86 the eax register.
			//

			ULONG64   BreakpointWithStatus;       // address of breakpoint

			//
			// Address of the saved context record during a bugcheck
			//
			// N.B. This is an automatic in KeBugcheckEx's frame, and
			// is only valid after a bugcheck.
			//

			ULONG64   SavedContext;

			//
			// help for walking stacks with user callbacks:
			//

			//
			// The address of the thread structure is provided in the
			// WAIT_STATE_CHANGE packet.  This is the offset from the base of
			// the thread structure to the pointer to the kernel stack frame
			// for the currently active usermode callback.
			//

			USHORT  ThCallbackStack;            // offset in thread data

			//
			// these values are offsets into that frame:
			//

			USHORT  NextCallback;               // saved pointer to next callback frame
			USHORT  FramePointer;               // saved frame pointer

			//
			// pad to a quad boundary
			//
			USHORT  PaeEnabled;

			//
			// Address of the kernel callout routine.
			//

			ULONG64   KiCallUserMode;             // kernel routine

			//
			// Address of the usermode entry point for callbacks.
			//

			ULONG64   KeUserCallbackDispatcher;   // address in ntdll


			//
			// Addresses of various kernel data structures and lists
			// that are of interest to the kernel debugger.
			//

			ULONG64   PsLoadedModuleList;
			ULONG64   PsActiveProcessHead;
			ULONG64   PspCidTable;

			ULONG64   ExpSystemResourcesList;
			ULONG64   ExpPagedPoolDescriptor;
			ULONG64   ExpNumberOfPagedPools;

			ULONG64   KeTimeIncrement;
			ULONG64   KeBugCheckCallbackListHead;
			ULONG64   KiBugcheckData;

			ULONG64   IopErrorLogListHead;

			ULONG64   ObpRootDirectoryObject;
			ULONG64   ObpTypeObjectType;

			ULONG64   MmSystemCacheStart;
			ULONG64   MmSystemCacheEnd;
			ULONG64   MmSystemCacheWs;

			ULONG64   MmPfnDatabase;
			ULONG64   MmSystemPtesStart;
			ULONG64   MmSystemPtesEnd;
			ULONG64   MmSubsectionBase;
			ULONG64   MmNumberOfPagingFiles;

			ULONG64   MmLowestPhysicalPage;
			ULONG64   MmHighestPhysicalPage;
			ULONG64   MmNumberOfPhysicalPages;

			ULONG64   MmMaximumNonPagedPoolInBytes;
			ULONG64   MmNonPagedSystemStart;
			ULONG64   MmNonPagedPoolStart;
			ULONG64   MmNonPagedPoolEnd;

			ULONG64   MmPagedPoolStart;
			ULONG64   MmPagedPoolEnd;
			ULONG64   MmPagedPoolInformation;
			ULONG64   MmPageSize;

			ULONG64   MmSizeOfPagedPoolInBytes;

			ULONG64   MmTotalCommitLimit;
			ULONG64   MmTotalCommittedPages;
			ULONG64   MmSharedCommit;
			ULONG64   MmDriverCommit;
			ULONG64   MmProcessCommit;
			ULONG64   MmPagedPoolCommit;
			ULONG64   MmExtendedCommit;

			ULONG64   MmZeroedPageListHead;
			ULONG64   MmFreePageListHead;
			ULONG64   MmStandbyPageListHead;
			ULONG64   MmModifiedPageListHead;
			ULONG64   MmModifiedNoWritePageListHead;
			ULONG64   MmAvailablePages;
			ULONG64   MmResidentAvailablePages;

			ULONG64   PoolTrackTable;
			ULONG64   NonPagedPoolDescriptor;

			ULONG64   MmHighestUserAddress;
			ULONG64   MmSystemRangeStart;
			ULONG64   MmUserProbeAddress;

			ULONG64   KdPrintCircularBuffer;
			ULONG64   KdPrintCircularBufferEnd;
			ULONG64   KdPrintWritePointer;
			ULONG64   KdPrintRolloverCount;

			ULONG64   MmLoadedUserImageList;

			// NT 5.1 Addition

			ULONG64   NtBuildLab;
			ULONG64   KiNormalSystemCall;

			// NT 5.0 hotfix addition

			ULONG64   KiProcessorBlock;
			ULONG64   MmUnloadedDrivers;
			ULONG64   MmLastUnloadedDriver;
			ULONG64   MmTriageActionTaken;
			ULONG64   MmSpecialPoolTag;
			ULONG64   KernelVerifier;
			ULONG64   MmVerifierData;
			ULONG64   MmAllocatedNonPagedPool;
			ULONG64   MmPeakCommitment;
			ULONG64   MmTotalCommitLimitMaximum;
			ULONG64   CmNtCSDVersion;

			// NT 5.1 Addition

			ULONG64   MmPhysicalMemoryBlock;
			ULONG64   MmSessionBase;
			ULONG64   MmSessionSize;
			ULONG64   MmSystemParentTablePage;

			// Server 2003 addition

			ULONG64   MmVirtualTranslationBase;

			USHORT    OffsetKThreadNextProcessor;
			USHORT    OffsetKThreadTeb;
			USHORT    OffsetKThreadKernelStack;
			USHORT    OffsetKThreadInitialStack;

			USHORT    OffsetKThreadApcProcess;
			USHORT    OffsetKThreadState;
			USHORT    OffsetKThreadBStore;
			USHORT    OffsetKThreadBStoreLimit;

			USHORT    SizeEProcess;
			USHORT    OffsetEprocessPeb;
			USHORT    OffsetEprocessParentCID;
			USHORT    OffsetEprocessDirectoryTableBase;

			USHORT    SizePrcb;
			USHORT    OffsetPrcbDpcRoutine;
			USHORT    OffsetPrcbCurrentThread;
			USHORT    OffsetPrcbMhz;

			USHORT    OffsetPrcbCpuType;
			USHORT    OffsetPrcbVendorString;
			USHORT    OffsetPrcbProcStateContext;
			USHORT    OffsetPrcbNumber;

			USHORT    SizeEThread;

			ULONG64   KdPrintCircularBufferPtr;
			ULONG64   KdPrintBufferSize;

			ULONG64   KeLoaderBlock;

			USHORT    SizePcr;
			USHORT    OffsetPcrSelfPcr;
			USHORT    OffsetPcrCurrentPrcb;
			USHORT    OffsetPcrContainedPrcb;

			USHORT    OffsetPcrInitialBStore;
			USHORT    OffsetPcrBStoreLimit;
			USHORT    OffsetPcrInitialStack;
			USHORT    OffsetPcrStackLimit;

			USHORT    OffsetPrcbPcrPage;
			USHORT    OffsetPrcbProcStateSpecialReg;
			USHORT    GdtR0Code;
			USHORT    GdtR0Data;

			USHORT    GdtR0Pcr;
			USHORT    GdtR3Code;
			USHORT    GdtR3Data;
			USHORT    GdtR3Teb;

			USHORT    GdtLdt;
			USHORT    GdtTss;
			USHORT    Gdt64R3CmCode;
			USHORT    Gdt64R3CmTeb;

			ULONG64   IopNumTriageDumpDataBlocks;
			ULONG64   IopTriageDumpDataBlocks;

			// Longhorn addition

			ULONG64   VfCrashDataBlock;
			ULONG64   MmBadPagesDetected;
			ULONG64   MmZeroedPageSingleBitErrorsDetected;

			// Windows 7 addition

			ULONG64   EtwpDebuggerData;
			USHORT    OffsetPrcbContext;

			// Windows 8 addition

			USHORT    OffsetPrcbMaxBreakpoints;
			USHORT    OffsetPrcbMaxWatchpoints;

			ULONG     OffsetKThreadStackLimit;
			ULONG     OffsetKThreadStackBase;
			ULONG     OffsetKThreadQueueListEntry;
			ULONG     OffsetEThreadIrpList;

			USHORT    OffsetPrcbIdleThread;
			USHORT    OffsetPrcbNormalDpcState;
			USHORT    OffsetPrcbDpcStack;
			USHORT    OffsetPrcbIsrStack;

			USHORT    SizeKDPC_STACK_FRAME;

			// Windows 8.1 Addition

			USHORT    OffsetKPriQueueThreadListHead;
			USHORT    OffsetKThreadWaitReason;

			// Windows 10 RS1 Addition

			USHORT    Padding;
			ULONG64   PteBase;

			// Windows 10 RS5 Addition

			ULONG64 RetpolineStubFunctionTable;
			ULONG RetpolineStubFunctionTableSize;
			ULONG RetpolineStubOffset;
			ULONG RetpolineStubSize;

		} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;
------------------------------------------------------------------------------------------

==========================================================================================
FILE #16
RELATIVE PATH: PicoSpoofer\src\Utils\PatternScan\PatternScan.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Utils\PatternScan\PatternScan.cpp
SIZE: 2146 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------

==========================================================================================
FILE #17
RELATIVE PATH: PicoSpoofer\src\Utils\PatternScan\PatternScan.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Utils\PatternScan\PatternScan.h
SIZE: 454 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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
------------------------------------------------------------------------------------------

==========================================================================================
FILE #18
RELATIVE PATH: PicoSpoofer\src\Utils\Utils.cpp
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Utils\Utils.cpp
SIZE: 4524 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------

==========================================================================================
FILE #19
RELATIVE PATH: PicoSpoofer\src\Utils\Utils.h
FULL PATH: C:\Users\Muslim\Desktop\Pico\PicoSpoofer\PicoSpoofer\PicoSpoofer\src\Utils\Utils.h
SIZE: 767 bytes
==========================================================================================

CODE / CONTENT:
------------------------------------------------------------------------------------------
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

------------------------------------------------------------------------------------------
