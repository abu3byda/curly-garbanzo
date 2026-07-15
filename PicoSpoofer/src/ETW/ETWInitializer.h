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
