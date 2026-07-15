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
