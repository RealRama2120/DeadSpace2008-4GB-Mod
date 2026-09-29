#pragma once
#include <intrin.h>
#include "vendor/minhook-1.3.4/include/MinHook.h"

// The Steam wrapper compares the loaded PE header with the original file.
// Windows has already established the large address space before DLL entry.
// Keep that address space, but present the verified original bytes to Steam.
// This is enabled only for the exact Steam executable tested with this mod.
static wchar_t g_steamGamePath[4096], g_steamBackupPath[4096];
static HANDLE g_steamTargetGuard=INVALID_HANDLE_VALUE;
static HANDLE g_steamDirectoryGuard=INVALID_HANDLE_VALUE;
static HANDLE g_steamBackupGuard=INVALID_HANDLE_VALUE;
typedef HANDLE (WINAPI* SteamCreateFileAFn)(LPCSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef HANDLE (WINAPI* SteamCreateFileWFn)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
static SteamCreateFileAFn g_steamCreateFileA=NULL;
static SteamCreateFileWFn g_steamCreateFileW=NULL;

static bool SteamReadOfGame(LPCWSTR path,DWORD access,DWORD creation,DWORD flags,void* caller)
{
    // Our own patch verification must see the actual on-disk LAA executable.
    MEMORY_BASIC_INFORMATION memory={};
    if(!path || !VirtualQuery(caller,&memory,sizeof(memory)) || memory.AllocationBase==g_self ||
       creation!=OPEN_EXISTING || (access & ~(GENERIC_READ | FILE_GENERIC_READ)) ||
       (flags & FILE_FLAG_DELETE_ON_CLOSE)) return false;
    wchar_t full[4096];
    DWORD len=GetFullPathNameW(path,ARRAYSIZE(full),full,NULL);
    return len && len<ARRAYSIZE(full) && !_wcsicmp(full,g_steamGamePath);
}

static HANDLE WINAPI SteamCreateFileA(LPCSTR path,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES sa,DWORD creation,DWORD flags,HANDLE templateFile)
{
    wchar_t wide[4096];
    if(path && MultiByteToWideChar(CP_ACP,0,path,-1,wide,ARRAYSIZE(wide)) &&
       SteamReadOfGame(wide,access,creation,flags,_ReturnAddress())) {
        return g_steamCreateFileW(g_steamBackupPath,access,share,sa,creation,flags,templateFile);
    }
    return g_steamCreateFileA(path,access,share,sa,creation,flags,templateFile);
}

static HANDLE WINAPI SteamCreateFileW(LPCWSTR path,DWORD access,DWORD share,LPSECURITY_ATTRIBUTES sa,DWORD creation,DWORD flags,HANDLE templateFile)
{
    if(SteamReadOfGame(path,access,creation,flags,_ReturnAddress())) {
        return g_steamCreateFileW(g_steamBackupPath,access,share,sa,creation,flags,templateFile);
    }
    return g_steamCreateFileW(path,access,share,sa,creation,flags,templateFile);
}

static void CloseSteamGuards()
{
    HANDLE* guards[]={&g_steamBackupGuard,&g_steamTargetGuard,&g_steamDirectoryGuard};
    for(size_t i=0;i<ARRAYSIZE(guards);++i) {
        if(*guards[i]!=INVALID_HANDLE_VALUE) CloseHandle(*guards[i]);
        *guards[i]=INVALID_HANDLE_VALUE;
    }
}

static void InitializeSteamCompatibility()
{
    wchar_t path[4096];
    DWORD length=GetModuleFileNameW(NULL,path,ARRAYSIZE(path));
    if(!length || length>=ARRAYSIZE(path) || _wcsicmp(BaseName(path),kGameName) || HighIntegrityOrUnknown()) return;
    BYTE* base=(BYTE*)GetModuleHandleW(NULL);
    IMAGE_DOS_HEADER* dos=(IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS32* nt=(IMAGE_NT_HEADERS32*)(base+dos->e_lfanew);
    if(nt->FileHeader.TimeDateStamp!=0x493e043a || nt->FileHeader.NumberOfSections!=6 ||
       !(nt->FileHeader.Characteristics&IMAGE_FILE_LARGE_ADDRESS_AWARE)) return;
    IMAGE_SECTION_HEADER* sections=IMAGE_FIRST_SECTION(nt);
    if(memcmp(sections[5].Name,".bind",5)) return;

    static const BYTE supportedPatched[32]={0x22,0x26,0x5f,0xd9,0xa4,0x10,0x4e,0x3b,0x86,0x83,0x13,0x4c,0x23,0x9d,0x03,0x10,0x88,0x9a,0xf9,0x97,0x9b,0xfa,0x40,0x77,0xd5,0xa6,0x1d,0x2c,0xbc,0x4c,0xaf,0x27};
    static const BYTE supportedOriginal[32]={0x81,0xae,0xb1,0x58,0xc2,0xfc,0x75,0x66,0x07,0xc7,0xdc,0xdb,0x3d,0xd2,0x99,0x52,0xc8,0x76,0x08,0xea,0x6c,0xab,0x2c,0xc6,0x5c,0x09,0xfb,0xf6,0x56,0xb2,0x94,0xf2};
    wcscpy_s(g_steamGamePath,path);
    _snwprintf_s(g_steamBackupPath,ARRAYSIZE(g_steamBackupPath),_TRUNCATE,L"%s.deadspace-laa.bak",path);
    BYTE digest[32],backupDigest[32];
    if(!OpenPinnedTarget(path,GENERIC_READ,&g_steamTargetGuard,&g_steamDirectoryGuard)) return;
    g_steamBackupGuard=CreateFileW(g_steamBackupPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,NULL);
    if(!NormalFileHandle(g_steamBackupGuard) || !Sha256Handle(g_steamBackupGuard,backupDigest) ||
       !SameHash(backupDigest,supportedOriginal) || !ValidatePatchedState(path,digest) ||
       !SameHash(digest,supportedPatched) || !PathStillNamesPinnedFile(path,g_steamTargetGuard) ||
       !PathStillNamesPinnedFile(g_steamBackupPath,g_steamBackupGuard)) {
        Log(L"Steam compatibility refused: executable or original backup is not the verified supported build.");
        CloseSteamGuards(); return;
    }

    HMODULE kernel=GetModuleHandleW(L"kernel32.dll");
    void* createA=(void*)GetProcAddress(kernel,"CreateFileA");
    void* createW=(void*)GetProcAddress(kernel,"CreateFileW");
    if(MH_Initialize()!=MH_OK) { CloseSteamGuards(); return; }
    DWORD oldProtect=0,ignored=0;
    if(MH_CreateHook(createA,(void*)&SteamCreateFileA,(void**)&g_steamCreateFileA)!=MH_OK ||
       MH_CreateHook(createW,(void*)&SteamCreateFileW,(void**)&g_steamCreateFileW)!=MH_OK ||
       MH_EnableHook(MH_ALL_HOOKS)!=MH_OK ||
       !VirtualProtect(&nt->FileHeader.Characteristics,sizeof(WORD),PAGE_READWRITE,&oldProtect)) {
        MH_Uninitialize(); CloseSteamGuards();
        Log(L"Steam compatibility hook setup failed; loaded header was left unchanged."); return;
    }
    nt->FileHeader.Characteristics &= ~IMAGE_FILE_LARGE_ADDRESS_AWARE;
    if(!VirtualProtect(&nt->FileHeader.Characteristics,sizeof(WORD),oldProtect,&ignored))
        Log(L"Steam loaded header protection could not be restored.");
    void* high=VirtualAlloc((void*)0x90000000,0x1000,MEM_RESERVE,PAGE_NOACCESS);
    Log(high==(void*)0x90000000 ? L"Steam compatibility active; real allocation above 2GB succeeded." :
        L"Steam compatibility active; high-address probe unavailable.");
    if(high) VirtualFree(high,0,MEM_RELEASE);
    // Keep both verified files and their containing directory pinned until exit.
}
