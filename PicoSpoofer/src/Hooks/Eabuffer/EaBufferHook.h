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