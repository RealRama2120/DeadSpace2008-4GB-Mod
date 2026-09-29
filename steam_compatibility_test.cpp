#include "dsound_one_dll.cpp"
#include <cstdio>

static void Require(bool value,const char* message) {
    if(!value){std::fprintf(stderr,"FAIL: %s\n",message);ExitProcess(1);}
}
static void Put(const wchar_t* path,char byte) {
    HANDLE file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,CREATE_ALWAYS,0,NULL);
    DWORD written=0;
    Require(file!=INVALID_HANDLE_VALUE && WriteFile(file,&byte,1,&written,NULL) && written==1,"fixture file creation");
    CloseHandle(file);
}
static char Read(HANDLE file) {
    char byte=0;DWORD read=0;
    Require(file!=INVALID_HANDLE_VALUE && ReadFile(file,&byte,1,&read,NULL) && read==1,"fixture read");
    CloseHandle(file);return byte;
}
int wmain(int argc,wchar_t** argv) {
    Require(argc==2,"explicit isolated directory required");
    _snwprintf_s(g_steamGamePath,ARRAYSIZE(g_steamGamePath),_TRUNCATE,L"%s\\target.exe",argv[1]);
    _snwprintf_s(g_steamBackupPath,ARRAYSIZE(g_steamBackupPath),_TRUNCATE,L"%s\\original.bak",argv[1]);
    wchar_t other[4096];_snwprintf_s(other,ARRAYSIZE(other),_TRUNCATE,L"%s\\other.txt",argv[1]);
    Put(g_steamGamePath,'P');Put(g_steamBackupPath,'O');Put(other,'X');
    HMODULE kernel=GetModuleHandleW(L"kernel32.dll");
    Require(MH_Initialize()==MH_OK,"MinHook initialization");
    Require(MH_CreateHook((void*)GetProcAddress(kernel,"CreateFileA"),(void*)&SteamCreateFileA,(void**)&g_steamCreateFileA)==MH_OK,"A hook");
    Require(MH_CreateHook((void*)GetProcAddress(kernel,"CreateFileW"),(void*)&SteamCreateFileW,(void**)&g_steamCreateFileW)==MH_OK,"W hook");
    Require(MH_EnableHook(MH_ALL_HOOKS)==MH_OK,"hook enable");
    auto open=[](const wchar_t* path){return CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);};
    g_self=GetModuleHandleW(NULL);
    Require(Read(open(g_steamGamePath))=='P',"mod's own checks see actual executable");
    g_self=kernel; // Model a caller outside the proxy DLL.
    Require(Read(open(g_steamGamePath))=='O',"external wide read sees original");
    char ansi[4096];Require(WideCharToMultiByte(CP_ACP,0,g_steamGamePath,-1,ansi,ARRAYSIZE(ansi),NULL,NULL)!=0,"ANSI path");
    Require(Read(CreateFileA(ansi,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL))=='O',"external ANSI read sees original");
    Require(Read(open(other))=='X',"unrelated file unchanged");
    void* caller=(void*)&wmain;
    const DWORD writeAccess[]={GENERIC_WRITE,GENERIC_ALL,FILE_WRITE_DATA,FILE_APPEND_DATA,FILE_WRITE_EA,FILE_WRITE_ATTRIBUTES,DELETE,WRITE_DAC,WRITE_OWNER};
    for(DWORD access: writeAccess)
        Require(!SteamReadOfGame(g_steamGamePath,access,OPEN_EXISTING,0,caller),"write/delete access must never redirect");
    Require(!SteamReadOfGame(g_steamGamePath,GENERIC_READ,CREATE_ALWAYS,0,caller),"create must never redirect");
    Require(!SteamReadOfGame(g_steamGamePath,GENERIC_READ,OPEN_EXISTING,FILE_FLAG_DELETE_ON_CLOSE,caller),"delete-on-close must never redirect");
    HANDLE write=CreateFileW(g_steamGamePath,FILE_WRITE_DATA,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    DWORD count=0;char changed='Q';
    Require(write!=INVALID_HANDLE_VALUE && WriteFile(write,&changed,1,&count,NULL) && count==1,"actual target write remains normal");
    CloseHandle(write);
    Require(MH_Uninitialize()==MH_OK,"hook cleanup");
    Require(Read(open(g_steamGamePath))=='Q' && Read(open(g_steamBackupPath))=='O',"write touched only actual target; cleanup restores real reads");
    std::puts("PASS: real ANSI/wide hooks, self-check exclusion, unrelated files, all write/delete access classes, create/delete flags, original backup preservation and unhooking.");
    return 0;
}
