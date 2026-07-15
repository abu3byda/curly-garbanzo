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
