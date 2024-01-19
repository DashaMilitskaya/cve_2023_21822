#ifndef _UMPD
#define _UMPD

#include <Windows.h>
#include <winddi.h>

#pragma pack(push, 1)
typedef struct _My_My_UMTHDR {
  DWORD cjSize;
  DWORD ulType;
  DWORD ulReserved1;
  DWORD ulReserved2;
} My_My_UMTHDR, *ptr_My_My_UMTHDR;
typedef struct _My_UMPDTHDR {
  My_My_UMTHDR umthdr;
  ULONG64      humpd;
} My_UMPDTHDR, *ptr_My_UMPDTHDR;
typedef struct _My_DRVSTARTDOCINPUT {
  My_UMPDTHDR umpdthdr;
  PVOID pso;
  PWSTR pwszDocName;
  DWORD dwJobId;
}  My_DRVSTARTDOCINPUT, *ptr_My_DRVSTARTDOCINPUT;
typedef struct _My_STORKEANDFILLINPUT {
  My_UMPDTHDR umpdthdr;
  PVOID pso;
  PVOID ppo;
  PVOID pco;
  PVOID pxo;
  PVOID pbo;
  PVOID pptlBrushOrg;
  PVOID plineattrs;
  PVOID gap_50_8h;
  ULONG32 gap_58_4h;
  ULONG32 gap_5C_4h;
}  My_STORKEANDFILLINPUT, *ptr_My_STORKEANDFILLINPUT;
typedef struct _My_DRVENABLEPDEVINPUT {
  My_UMPDTHDR umpdthdr;
  PVOID umpdcookie;
  PVOID pdm;
  PVOID pLogAddress;
  ULONG32 cPatterns;
  ULONG32 gap_34_4h;
  PVOID phsurfPatterns;
  ULONG32 cjCaps;
  ULONG32 gap_44_Ch[3];
  ULONG32 cjDevInfo;
  ULONG32 gap_54_Ch[3];
  PVOID hdev;
  PVOID pDeviceName;
  PVOID hPrinter;
  ULONG32 bSandboxedCurrentProcess;
  ULONG32 clientPid;
  ULONG64 gap_80_8h;
  ULONG64 gap_88_8h;
  ULONG64 gap_90_8h;
  ULONG64 gap_98_8h;
  ULONG32 gap_A0_4h;
  ULONG32 gap_A4_4h;
  ULONG32 gap_A8_4h;
  ULONG32 gap_AC_4h;
} My_DRVENABLEPDEVINPUT, *ptr_My_DRVENABLEPDEVINPUT;
typedef struct _My_DRVENABLESURFACEINPUT {
  My_UMPDTHDR umpdthdr;
  ULONG64 hpdev;
} My_DRVENABLESURFACEINPUT, *ptr_My_DRVENABLESURFACEINPUT;
#pragma pack(pop)

struct My_UMSO {
  ULONG     magic;
  HBITMAP   hsurf;
  SURFOBJ   so;           
};

typedef INT (*FuncTy_GdiPrinterThunk_)( 
    VOID*     InputBuffer, 
    ULONGLONG SomeBufferSizeLimit, 
    VOID*     OutputBuffer, 
    ULONGLONG OutputBufferSize 
);


BOOL umpd_load_printer_dll(LPWSTR printerName, HANDLE& hPrinter, LPWSTR& pDriverPath, HMODULE& hPrinterDLL);
BOOL umpd_set_gdi_hooks();
VOID umpd_set_callback(INT index, FuncTy_GdiPrinterThunk_ cb, BOOL bBefore = TRUE, BOOL bCallOrig = TRUE);

INT umpd_gdi_think_hook(VOID *inputBuf, ULONGLONG inputBufSize, VOID *outputBuffer, ULONGLONG outputBufSize);

// 
BOOL util_hook_iat(HMODULE dll, char const* targetDLL, void *targetFunction, void* detourFunction);

#endif // _UMPD