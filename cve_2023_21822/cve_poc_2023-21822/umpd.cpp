#include "umpd.h"

#include <stdio.h>

#define NUMBER_UMPD_OF_CALLBACKS 256

typedef struct _UMPD_GDI_HOOK_INFO {
    FuncTy_GdiPrinterThunk_ pfnOrig;

    PULONG64 ptrOrigMem;

    FuncTy_GdiPrinterThunk_ pfnUmpdCallbackBefore[NUMBER_UMPD_OF_CALLBACKS] = {0};
    FuncTy_GdiPrinterThunk_ pfnUmpdCallbackAfter[NUMBER_UMPD_OF_CALLBACKS] = {0}; 

    BOOL bCallOrigTable[NUMBER_UMPD_OF_CALLBACKS] = {TRUE};

} UMPD_GDI_HOOK_INFO,*PUMPD_GDI_HOOK_INFO;

static UMPD_GDI_HOOK_INFO g_umpd_hook_info;


BOOL util_hook_iat_in_module(
    HMODULE hModule,
    HMODULE hModuleTarget,
    FARPROC pfnTarget,
    ULONG64 pfnHook,
    ULONG64& pfnOrig,
    PULONG64& ptrOrig
) {

    PBYTE base = (PBYTE)hModule;

    PIMAGE_DOS_HEADER        dos = (PIMAGE_DOS_HEADER)(hModule);
    PIMAGE_NT_HEADERS        fh  = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    IMAGE_OPTIONAL_HEADER64  opt = fh->OptionalHeader;
    IMAGE_DATA_DIRECTORY     dir = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR descs = (PIMAGE_IMPORT_DESCRIPTOR)(dir.VirtualAddress + base);

    BOOL bFound = FALSE;
    int i = 0;

    while (descs[i].Characteristics != 0) {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = &descs[i];
        
        HMODULE hImportedLib = LoadLibraryA(
            (char *)(importDesc->Name + base)
        );
        if (hImportedLib != hModuleTarget) {
            i++;
            continue;
        }

        PIMAGE_THUNK_DATA64 nameTable = (PIMAGE_THUNK_DATA64)(importDesc->OriginalFirstThunk + base);
        PIMAGE_THUNK_DATA64 addrTable = (PIMAGE_THUNK_DATA64)(importDesc->FirstThunk + base);

        int j = 0;
        while (nameTable[j].u1.AddressOfData != 0 ) {
            PIMAGE_THUNK_DATA64 nameDesc = &nameTable[j];
            PIMAGE_THUNK_DATA64 addrDesc = &addrTable[j];

            BOOL bImportedByOrdinal = (nameDesc->u1.Ordinal & IMAGE_ORDINAL_FLAG) == IMAGE_ORDINAL_FLAG;
            if (bImportedByOrdinal) {
                j++;
                continue;
            }

            
            PIMAGE_IMPORT_BY_NAME importedFuncName = (PIMAGE_IMPORT_BY_NAME)(nameDesc->u1.AddressOfData + base);
            FARPROC               importedFunc = GetProcAddress(hImportedLib, (char*)(&importedFuncName->Name));
  
            if (importedFunc != pfnTarget) {
                j++;
                continue;
            }

            ptrOrig = &addrDesc->u1.Function;
            DWORD protectFlags = NULL;
            
            VirtualProtect(ptrOrig, sizeof(ULONG64), PAGE_READWRITE, &protectFlags);
            pfnOrig = *ptrOrig;
            *ptrOrig = pfnHook;
            VirtualProtect(ptrOrig, sizeof(ULONG64), protectFlags, &protectFlags);
            
            bFound = TRUE;
            break;
        }
        
        break;
    }

    return bFound;
};


BOOL umpd_load_printer_dll(LPWSTR printerName, HANDLE& hPrinter, LPWSTR& pDriverPath, HMODULE& hPrinterDLL) {
    hPrinter = NULL;
    pDriverPath = NULL;

    if (!OpenPrinterW(printerName, &hPrinter, NULL)) {
        return FALSE;
    }
  
    DWORD pcbNeeded;
    GetPrinterDriverW(hPrinter, NULL, 2, NULL, 0, &pcbNeeded);
    DRIVER_INFO_2W* driverInfo = (DRIVER_INFO_2W*)malloc(pcbNeeded);
    if (!GetPrinterDriverW(hPrinter, NULL, 2, (LPBYTE)driverInfo, pcbNeeded, &pcbNeeded)) {
        ClosePrinter(hPrinter);

        return FALSE;
    }
    pDriverPath = driverInfo->pDriverPath;
    hPrinterDLL = LoadLibraryExW(driverInfo->pDriverPath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

    return TRUE;
};


INT umpd_gdi_think_hook(VOID *inputBuf, ULONGLONG inputBufSize, VOID *outputBuffer, ULONGLONG outputBufSize) {
    ptr_My_UMPDTHDR umpdthdr = (ptr_My_UMPDTHDR)inputBuf;

    wprintf(
        L"[?][umpd_gdi_think_hook] in=%p out=%p szout=%llx cjSize=%x ulType=%d ulReserved1=%x ulReserved2=%x humpd=%llx\n",
        inputBuf, 
        outputBuffer, 
        outputBufSize,
        umpdthdr->umthdr.cjSize,
        umpdthdr->umthdr.ulType,
        umpdthdr->umthdr.ulReserved1,
        umpdthdr->umthdr.ulReserved2,
        umpdthdr->humpd
    );
    
    INT result  = TRUE;

    if (g_umpd_hook_info.pfnUmpdCallbackBefore[umpdthdr->umthdr.ulType]) {
        result = g_umpd_hook_info.pfnUmpdCallbackBefore[umpdthdr->umthdr.ulType](
            inputBuf, inputBufSize, outputBuffer, outputBufSize
        );
    }

    if (g_umpd_hook_info.bCallOrigTable[umpdthdr->umthdr.ulType]) {
        result = g_umpd_hook_info.pfnOrig(
            inputBuf, inputBufSize, outputBuffer, outputBufSize
        );
    }

    if (g_umpd_hook_info.pfnUmpdCallbackAfter[umpdthdr->umthdr.ulType]) {
        result = g_umpd_hook_info.pfnUmpdCallbackAfter[umpdthdr->umthdr.ulType](
            inputBuf, inputBufSize, outputBuffer, outputBufSize
        );
    }

    return result;
}

BOOL umpd_set_gdi_hooks() {
   
    HMODULE hgdi = LoadLibraryW(L"gdi32.dll");
    HMODULE hu32 = LoadLibraryW(L"user32.dll");
    if (!hgdi || !hu32)
        return FALSE;
    printf("gdi ans user dll finded");
    BOOL status = util_hook_iat_in_module(
        hu32,
        hgdi,
        GetProcAddress(hgdi, "GdiPrinterThunk"),
        (ULONG64)&umpd_gdi_think_hook,
        (ULONG64&)g_umpd_hook_info.pfnOrig,
        g_umpd_hook_info.ptrOrigMem
    );

    memset(&g_umpd_hook_info.bCallOrigTable, TRUE, 256 * sizeof(BOOL));
    return status;
};

VOID umpd_set_callback(INT index, FuncTy_GdiPrinterThunk_ cb, BOOL bBefore, BOOL bCallOrig) {
    if (bBefore)
        g_umpd_hook_info.pfnUmpdCallbackBefore[index] = cb;
    else
        g_umpd_hook_info.pfnUmpdCallbackAfter[index] = cb;

    g_umpd_hook_info.bCallOrigTable[index] = bCallOrig;
}