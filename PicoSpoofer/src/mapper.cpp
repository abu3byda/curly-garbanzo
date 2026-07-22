#include "mapper.h"
#include <winternl.h>

// دالة مساعدة: تطبيق Relocations (زي FUN_140031320)
void ApplyRelocations(PVOID ImageBase, ULONG_PTR Delta) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ImageBase + pDos->e_lfanew);
    PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)ImageBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    
    while (pReloc->VirtualAddress) {
        PWORD pRelocData = (PWORD)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));
        for (DWORD i = 0; i < (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2; i++) {
            if ((pRelocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                ULONG_PTR* pPatch = (ULONG_PTR*)((BYTE*)ImageBase + pReloc->VirtualAddress + (pRelocData[i] & 0xFFF));
                *pPatch += Delta;
            }
        }
        pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
    }
}

// دالة ربط الـ Imports (زي FUN_1400313b0)
void ResolveImports(PVOID ImageBase) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)ImageBase + pDos->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)ImageBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    
    while (pImport->Name) {
        LPCSTR DllName = (LPCSTR)((BYTE*)ImageBase + pImport->Name);
        HMODULE hDll = GetModuleHandleA(DllName);
        if (!hDll) continue;

        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)ImageBase + pImport->FirstThunk);
        PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((BYTE*)ImageBase + pImport->OriginalFirstThunk);
        if (!pIAT) pIAT = pThunk;

        while (pThunk->u1.Function) {
            if ((pIAT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) == 0) {
                PIMAGE_IMPORT_BY_NAME pByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)ImageBase + pIAT->u1.AddressOfData);
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll, pByName->Name);
            } else {
                pThunk->u1.Function = (ULONG_PTR)GetProcAddress(hDll, (LPCSTR)(pIAT->u1.Ordinal & 0xFFFF));
            }
            pThunk++, pIAT++;
        }
        pImport++;
    }
}

// الدالة الرئيسية (بديل FUN_1400314a0)
PVOID ManualMapDriver(PVOID DriverData, SIZE_T DriverSize) {
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)DriverData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)DriverData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // 1. نخصص ذاكرة في مساحة النواة (عن طريق VirtualAlloc، لكن في الواقع هتبعت IOCTL للـ Kernel)
    //    هنا هنعملها تجربة في مساحة المستخدم لعمل الاختبار، لكن في الواقع هتبعت الأمر للسائق.
    //    بس عشان المشروع يشتغل، هنخصصها في المستخدم مؤقتاً.
    PVOID KernelBase = VirtualAlloc(NULL, pNt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!KernelBase) return NULL;

    // 2. نسخ الـ Sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (pSection[i].SizeOfRawData) {
            memcpy((BYTE*)KernelBase + pSection[i].VirtualAddress, (BYTE*)DriverData + pSection[i].PointerToRawData, pSection[i].SizeOfRawData);
        }
    }

    // 3. تطبيق Relocations
    ULONG_PTR Delta = (ULONG_PTR)KernelBase - pNt->OptionalHeader.ImageBase;
    if (Delta) {
        ApplyRelocations(KernelBase, Delta);
    }

    // 4. ربط الـ Imports
    ResolveImports(KernelBase);

    // 5. استدعاء EntryPoint (DllMain / DriverEntry)
    PIMAGE_DATA_DIRECTORY pEntry = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
    if (pEntry->VirtualAddress) {
        // في السائق، EntryPoint هو DriverEntry
        // لكن السائقين في النواة بيحتاجوا IRQL ومتطلبات تانية.
        // هنكتفي بالـ Mapping فقط للتوضيح.
    }

    return KernelBase;
}