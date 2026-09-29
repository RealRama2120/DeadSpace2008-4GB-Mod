#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mmsystem.h>
#include <dsound.h>
#include <stdio.h>

extern "C" HRESULT WINAPI DllCanUnloadNow();
extern "C" HRESULT WINAPI DllGetClassObject(REFCLSID, REFIID, LPVOID*);

static BOOL CALLBACK EnumerateA(LPGUID, LPCSTR, LPCSTR, LPVOID) { return TRUE; }
static BOOL CALLBACK EnumerateW(LPGUID, LPCWSTR, LPCWSTR, LPVOID) { return TRUE; }

static bool IsLaa()
{
    wchar_t path[32768];
    if (!GetModuleFileNameW(NULL, path, ARRAYSIZE(path))) return false;
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return false;
    IMAGE_DOS_HEADER dos = {};
    DWORD n = 0;
    bool result = false;
    if (ReadFile(f, &dos, sizeof(dos), &n, NULL) && n == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE)
    {
        LARGE_INTEGER at; at.QuadPart = dos.e_lfanew + sizeof(DWORD);
        IMAGE_FILE_HEADER coff = {};
        if (SetFilePointerEx(f, at, NULL, FILE_BEGIN) && ReadFile(f, &coff, sizeof(coff), &n, NULL) && n == sizeof(coff))
            result = (coff.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0;
    }
    CloseHandle(f);
    return result;
}

static DWORD IntegrityRid()
{
    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return 0;
    DWORD bytes = 0;
    GetTokenInformation(token, TokenIntegrityLevel, NULL, 0, &bytes);
    BYTE* buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, bytes);
    DWORD rid = 0;
    if (buffer && GetTokenInformation(token, TokenIntegrityLevel, buffer, bytes, &bytes))
    {
        TOKEN_MANDATORY_LABEL* label = (TOKEN_MANDATORY_LABEL*)buffer;
        DWORD count = *GetSidSubAuthorityCount(label->Label.Sid);
        rid = *GetSidSubAuthority(label->Label.Sid, count - 1);
    }
    if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(token);
    return rid;
}

int WINAPI wWinMain(HINSTANCE, HINSTANCE, wchar_t*, int)
{
    int forwarders = 0;
    LPDIRECTSOUND sound = NULL;
    if (SUCCEEDED(DirectSoundCreate(NULL, &sound, NULL)) && sound) sound->Release();
    ++forwarders;
    DirectSoundEnumerateA(EnumerateA, NULL); ++forwarders;
    DirectSoundEnumerateW(EnumerateW, NULL); ++forwarders;
    DllCanUnloadNow(); ++forwarders;
    LPVOID classObject = NULL;
    DllGetClassObject(CLSID_NULL, IID_IUnknown, &classObject); ++forwarders;
    if (classObject) ((IUnknown*)classObject)->Release();
    LPDIRECTSOUNDCAPTURE capture = NULL;
    if (SUCCEEDED(DirectSoundCaptureCreate(NULL, &capture, NULL)) && capture) capture->Release();
    ++forwarders;
    DirectSoundCaptureEnumerateA(EnumerateA, NULL); ++forwarders;
    DirectSoundCaptureEnumerateW(EnumerateW, NULL); ++forwarders;
    GUID device = {};
    GetDeviceID(&DSDEVID_DefaultPlayback, &device); ++forwarders;
    LPDIRECTSOUNDFULLDUPLEX duplex = NULL;
    LPDIRECTSOUNDCAPTUREBUFFER8 captureBuffer = NULL;
    LPDIRECTSOUNDBUFFER8 renderBuffer = NULL;
    DirectSoundFullDuplexCreate(NULL, NULL, NULL, NULL, NULL, 0, &duplex, &captureBuffer, &renderBuffer, NULL);
    if (renderBuffer) renderBuffer->Release(); if (captureBuffer) captureBuffer->Release(); if (duplex) duplex->Release();
    ++forwarders;
    LPDIRECTSOUND8 sound8 = NULL;
    if (SUCCEEDED(DirectSoundCreate8(NULL, &sound8, NULL)) && sound8) sound8->Release();
    ++forwarders;
    LPDIRECTSOUNDCAPTURE8 capture8 = NULL;
    if (SUCCEEDED(DirectSoundCaptureCreate8(NULL, &capture8, NULL)) && capture8) capture8->Release();
    ++forwarders;
    Sleep(750);

    wchar_t bypass[16] = L"";
    GetEnvironmentVariableW(L"DEADSPACE4GB_BYPASS", bypass, ARRAYSIZE(bypass));
    wchar_t sentinel[64] = L"";
    GetEnvironmentVariableW(L"DEADSPACE4GB_SENTINEL", sentinel, ARRAYSIZE(sentinel));
    wchar_t request[64] = L"";
    GetEnvironmentVariableW(L"DEADSPACE4GB_REQUEST", request, ARRAYSIZE(request));
    wchar_t role[64] = L"";
    GetEnvironmentVariableW(L"DEADSPACE4GB_RELAUNCH_ROLE", role, ARRAYSIZE(role));
    wchar_t elevated[16] = L"";
    GetEnvironmentVariableW(L"DEADSPACE4GB_ELEVATED_WORKER", elevated, ARRAYSIZE(elevated));
    wchar_t cwd[4096] = L"";
    GetCurrentDirectoryW(ARRAYSIZE(cwd), cwd);
    wchar_t row[65536];
    _snwprintf_s(row, ARRAYSIZE(row), _TRUNCATE, L"pid=%lu;integrityRid=%lu;laa=%d;bypass=%s;sentinel=%s;request=%s;role=%s;elevatedWorker=%s;forwarders=%d;cwd=%s;cmd=%s\r\n",
        GetCurrentProcessId(), IntegrityRid(), IsLaa() ? 1 : 0, bypass, sentinel, request, role, elevated,
        forwarders, cwd, GetCommandLineW());
    HANDLE log = CreateFileW(L"fixture-runs.log", FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log != INVALID_HANDLE_VALUE)
    {
        DWORD written = 0;
        WriteFile(log, row, (DWORD)(wcslen(row) * sizeof(wchar_t)), &written, NULL);
        FlushFileBuffers(log);
        CloseHandle(log);
    }
    return 0;
}
